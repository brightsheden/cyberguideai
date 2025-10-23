from django.shortcuts import render
from django.http import JsonResponse
import google.generativeai as genai
import markdown
from django.contrib import messages
from django.conf import settings
import json
import re
from . import tools
from .models import ChatSession, ChatMessage
import tempfile
import subprocess
import os
 
import traceback

# Create your views here.


def home(request):
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')

    if request.method == "POST":
        user_input = request.POST.get("user_input", "").strip()
        if not user_input:
            # If this is an XHR request return JSON error, otherwise use messages
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                return JsonResponse({'ok': False, 'error': 'Please provide a question or task.'}, status=400)
            messages.error(request, "Please provide a question or task.")
            return render(request, "home.html")

        # Prompt the model to return strict JSON following a defined schema.
        ai_prompts = f"""
You are SSU CyberGuide, a professional cybersecurity assistant.
Respond ONLY with a single JSON object (no surrounding text or markdown).
JSON schema:
{{
  "summary": "short plain-text summary of the recommendation",
  "checks": [
    {{
      "id": "unique-id",
      "title": "short title",
      "description": "detailed explanation",
      "commands": ["bash commands or snippets as strings"],
      "tools": ["recommended tools"],
      "severity": "low|medium|high",
      "automatable": true
    }}
  ],
  "warnings": ["safety or legal warnings"],
  "references": ["https://..."],
  "notes": "optional plain text notes"
}}

User question: {user_input}

Return valid JSON that conforms to the schema above. If a field is not applicable, return an empty list or null, but do not add any extra top-level keys.
"""

        try:
            gpt_response = model.generate_content(ai_prompts)
            raw = getattr(gpt_response, "text", str(gpt_response))
            print(raw)
        except Exception as e:
            raw = str(e)
            # If AJAX, return error JSON
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                return JsonResponse({'ok': False, 'error': 'AI engine error', 'raw': raw}, status=500)
            messages.error(request, "AI engine error: " + raw)
            return render(request, "home.html")

        # Try to extract JSON from code fence first, then any JSON object substring.
        json_text = None
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
        if m:
            json_text = m.group(1)
        else:
            # fallback: find the first balanced JSON object by searching for first { and last }.
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                json_text = raw[start:end + 1]

        parsed = None
        if json_text:
            try:
                parsed = json.loads(json_text)
            except json.JSONDecodeError:
                parsed = None

        if not parsed:
            # final fallback: return raw response as markdown for user to inspect
            # For AJAX requests return raw text so the client can display it
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                return JsonResponse({'ok': False, 'raw': raw})
            messages.warning(request, "Could not parse structured JSON from the AI. Showing raw output.")
            print(raw)
            rendered = markdown.markdown(raw)
            return render(request, "home.html", {"raw_output": rendered, "user_input": user_input})

        # Optionally validate minimal schema keys
        if "summary" not in parsed or "checks" not in parsed:
            # for AJAX requests, include a warn flag instead of Django messages
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                return JsonResponse({'ok': True, 'data': parsed, 'warning': 'Parsed JSON missing expected keys'})
            messages.warning(request, "Parsed JSON missing expected keys; displaying what was returned.")

        # Persist chat: append to existing session if provided, otherwise create session
        session = None
        session_reused = False
        try:
            session_id_raw = request.POST.get('session_id')
            session_id = None
            if session_id_raw is not None:
                sid_str = str(session_id_raw).strip()
                if sid_str and sid_str.lower() not in ('null', 'none', 'undefined'):
                    try:
                        session_id = int(sid_str)
                    except Exception:
                        session_id = None

            if session_id:
                try:
                    session = ChatSession.objects.get(pk=session_id)
                    session_reused = True
                except ChatSession.DoesNotExist:
                    session = None

            if not session:
                session = ChatSession.objects.create(title=(user_input[:80] + '...') if len(user_input) > 80 else user_input)

            # save user message
            ChatMessage.objects.create(session=session, role='user', content=user_input)

            # build assistant-friendly markdown from parsed JSON
            assistant_md = ''
            if isinstance(parsed, dict):
                assistant_md += parsed.get('summary', '') or ''
                checks = parsed.get('checks') if isinstance(parsed.get('checks'), list) else []
                if checks:
                    assistant_md += '\n\n'
                    for c in checks:
                        title = c.get('title') or c.get('id') or ''
                        desc = c.get('description') or ''
                        assistant_md += f"### {title}\n\n{desc}\n\n"
                if parsed.get('notes'):
                    assistant_md += '\n\n' + parsed.get('notes')
            else:
                assistant_md = str(parsed)

            # render markdown to HTML and save as assistant content
            try:
                assistant_html = markdown.markdown(assistant_md)
            except Exception:
                assistant_html = assistant_md

            ChatMessage.objects.create(session=session, role='assistant', content=assistant_html)
        except Exception:
            # non-fatal if DB not available; continue
            session = None
            session_reused = False

        # If this was an XHR request return parsed JSON and assistant HTML; otherwise render page
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            resp = {'ok': True, 'data': parsed}
            if session:
                resp['session_id'] = session.id
                resp['session_reused'] = bool(session_reused)
                # include last assistant message HTML for immediate rendering
                last_assistant = session.messages.filter(role='assistant').order_by('-created_at').first()
                resp['assistant_html'] = last_assistant.content if last_assistant else ''
            else:
                resp['session_reused'] = False
            return JsonResponse(resp)

        # Provide parsed data to template for full page render
        print(parsed)
        ctx = {"ai_json": parsed, "user_input": user_input}
        if session:
            ctx['session_id'] = session.id
        return render(request, "home.html", ctx)

    # GET
    return render(request, "home.html")


def link_page(request):
    """Render standalone link analyzer page."""
    return render(request, "link_analyzer.html")


def email_page(request):
    """Render standalone email analyzer page."""
    return render(request, "email_analyzer.html")


def analyze_link(request):
    """AJAX endpoint: passive link analysis using heuristics in bot.tools
    Expects POST with 'url' parameter.
    """
    if request.method != 'POST' or not (request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'):
        return JsonResponse({'ok': False, 'error': 'AJAX POST required'}, status=400)

    url = request.POST.get('url', '')
    result = tools.analyze_link(url)
    return JsonResponse({'ok': True, 'data': result})


def _save_temp_file(f):
    tmpdir = getattr(settings, 'UPLOAD_TMP_DIR', None) or tempfile.gettempdir()
    suffix = os.path.splitext(f.name)[1]
    fd, path = tempfile.mkstemp(prefix='upload_', suffix=suffix, dir=tmpdir)
    with os.fdopen(fd, 'wb') as out:
        for chunk in f.chunks():
            out.write(chunk)
    return path


def _sanitize_excerpt(code_snippet):
    # Basic redaction of private key blocks and very long base64-like tokens
    s = re.sub(r"-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----", '[REDACTED_KEY]', code_snippet)
    s = re.sub(r"[A-Za-z0-9+/]{60,}", '[REDACTED_TOKEN]', s)
    return s


def _get_excerpt(path, line, context=3):
    try:
        with open(path, 'r', errors='ignore') as fh:
            lines = fh.readlines()
        idx = max(0, int(line) - 1)
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        excerpt = ''.join(lines[start:end])
        return _sanitize_excerpt(excerpt)
    except Exception:
        return ''


def _run_bandit(path):
    try:
        cmd = ['bandit', '-f', 'json', '-r', path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Bandit returns exit code 1 if issues found, but still outputs JSON
        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                return {'error': f'Invalid JSON from bandit: {str(e)}', 'raw': proc.stdout}
        
        return {'error': f'No output from bandit. Exit code: {proc.returncode}', 'stderr': proc.stderr}
    except FileNotFoundError:
        return {'error': 'bandit not installed - run: pip install bandit'}
    except subprocess.TimeoutExpired:
        return {'error': 'bandit timed out after 30 seconds'}
    except Exception as e:
        return {'error': f'bandit exception: {str(e)}'}


def _run_semgrep(path):
    try:
        # Add --config auto to use default rulesets
        cmd = ['semgrep', '--config', 'auto', '--json', path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        
        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                return {'error': f'Invalid JSON from semgrep: {str(e)}', 'raw': proc.stdout}
        
        return {'error': f'No output from semgrep. Exit code: {proc.returncode}', 'stderr': proc.stderr}
    except FileNotFoundError:
        return {'error': 'semgrep not installed - run: pip install semgrep'}
    except subprocess.TimeoutExpired:
        return {'error': 'semgrep timed out after 40 seconds'}
    except Exception as e:
        return {'error': f'semgrep exception: {str(e)}'}

def scan_upload(request):
    """AJAX endpoint: upload a single file, run local static analyzers, optionally summarize with Gemini, and save to chat session."""
    if request.method != 'POST' or not (request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'):
        return JsonResponse({'ok': False, 'error': 'AJAX POST required'}, status=400)

    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'ok': False, 'error': 'no file uploaded'}, status=400)

    MAX_BYTES = getattr(settings, 'UPLOAD_MAX_BYTES', 2 * 1024 * 1024)
    if uploaded.size > MAX_BYTES:
        return JsonResponse({'ok': False, 'error': 'file too large'}, status=413)

    ALLOWED_EXT = getattr(settings, 'UPLOAD_ALLOWED_EXT', ['.py', '.js', '.java', '.go', '.cpp', '.c', '.rb'])
    ext = os.path.splitext(uploaded.name)[1].lower()
    if ext not in ALLOWED_EXT:
        return JsonResponse({'ok': False, 'error': 'unsupported file extension'}, status=400)

    tmp_path = None
    try:
        tmp_path = _save_temp_file(uploaded)
        findings = {}
        # Run bandit for Python
        if ext == '.py':
            findings['bandit'] = _run_bandit(tmp_path)

        # Try semgrep for all languages (if installed)
        findings['semgrep'] = _run_semgrep(tmp_path)

        # Build a compact findings summary
        compact = []
        # parse bandit
        b = findings.get('bandit')
        if isinstance(b, dict) and b.get('results'):
            for r in b.get('results', [])[:6]:
                compact.append({'tool': 'bandit', 'test_id': r.get('test_id'), 'issue_text': r.get('issue_text'), 'severity': r.get('issue_severity'), 'line': r.get('lineno')})

        # parse semgrep
        s = findings.get('semgrep')
        if isinstance(s, dict) and s.get('results'):
            for r in s.get('results', [])[:6]:
                line = None
                try:
                    line = r.get('start', {}).get('line')
                except Exception:
                    line = None
                compact.append({'tool': 'semgrep', 'rule_id': r.get('check_id') or r.get('rule_id') or r.get('id'), 'message': r.get('extra', {}).get('message') if isinstance(r.get('extra'), dict) else None, 'line': line})

        # Create short sanitized excerpts for each compact finding
        for c in compact:
            if c.get('line'):
                c['excerpt'] = _get_excerpt(tmp_path, c['line'])

        # Build assistant markdown from findings (local summary)
        assistant_md = f"## Scan results for {uploaded.name}\n\n"
        if compact:
            for c in compact:
                assistant_md += f"- {c.get('tool')} {c.get('test_id') or c.get('rule_id') or ''} (line {c.get('line', '?')}): {c.get('issue_text') or c.get('message') or ''}\n"
                if c.get('excerpt'):
                    assistant_md += "\n```\n" + (c.get('excerpt')[:1000]) + "\n```\n\n"
        else:
            # No compact findings — provide detailed tool outputs or errors to help debug
            assistant_md += "No specific findings from local analyzers.\n\n"
            # include bandit/semgrep status/errors
            try:
                b = findings.get('bandit')
                if b is None:
                    assistant_md += "Bandit: not run (not a Python file)\n"
                elif isinstance(b, dict) and b.get('error'):
                    assistant_md += f"Bandit error: {b.get('error')}\n"
                elif isinstance(b, dict) and b.get('results'):
                    assistant_md += f"Bandit ran: {len(b.get('results', []))} findings (not shown)\n"
                else:
                    assistant_md += "Bandit ran: no findings\n"
            except Exception:
                pass
            try:
                s = findings.get('semgrep')
                if s is None:
                    assistant_md += "Semgrep: not run\n"
                elif isinstance(s, dict) and s.get('error'):
                    assistant_md += f"Semgrep error: {s.get('error')}\n"
                elif isinstance(s, dict) and s.get('results'):
                    assistant_md += f"Semgrep ran: {len(s.get('results', []))} findings (not shown)\n"
                else:
                    assistant_md += "Semgrep ran: no findings\n"
            except Exception:
                pass
            assistant_md += "\nIf you expected findings, ensure Bandit and/or Semgrep are installed in the server environment and retry."

        assistant_html = markdown.markdown(assistant_md)

        # Optionally call Gemini to summarize & recommend (only if API key present)
        gemini_parsed = None
        if getattr(settings, 'GEMINI_API_KEY', None):
            try:
                genai.configure(api_key=settings.GEMINI_API_KEY)
                model = genai.GenerativeModel('gemini-2.5-flash')
                # create a small JSON-first prompt containing findings (not whole file)
                ai_prompt = f"You are a security assistant. Respond ONLY with JSON. Schema: {json.dumps({'summary':'','remediations':[]})}. Findings: {json.dumps(compact)}\nProvide prioritized remediations and commands."
                gresp = model.generate_content(ai_prompt)
                raw = getattr(gresp, 'text', str(gresp))
                # try to extract JSON from response
                jm = None
                m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", raw, re.S)
                if m:
                    jm = m.group(1)
                else:
                    start = raw.find('{')
                    end = raw.rfind('}')
                    if start != -1 and end != -1 and end>start:
                        jm = raw[start:end+1]
                if jm:
                    try:
                        gemini_parsed = json.loads(jm)
                        # render gemini summary into assistant_html as well
                        try:
                            gemini_md = gemini_parsed.get('summary','') + '\n\n'
                            for r in gemini_parsed.get('remediations',[])[:5]:
                                gemini_md += f"### {r.get('title','') }\n{r.get('description','')}\n\n"
                            assistant_html += '<hr/>' + markdown.markdown(gemini_md)
                        except Exception:
                            pass
                    except Exception:
                        gemini_parsed = None
            except Exception:
                # ignore AI errors; continue with local results
                traceback.print_exc()

        # Persist chat: append to session if provided
        session = None
        try:
            session_id = request.POST.get('session_id') or None
            if session_id:
                try:
                    session = ChatSession.objects.get(pk=int(session_id))
                except Exception:
                    session = None
            if not session:
                session = ChatSession.objects.create(title=(uploaded.name[:80] + '...') if len(uploaded.name)>80 else uploaded.name)
            ChatMessage.objects.create(session=session, role='user', content=f"Uploaded file: {uploaded.name}")
            ChatMessage.objects.create(session=session, role='assistant', content=assistant_html)
        except Exception:
            session = None

        resp = {'ok': True, 'findings': findings, 'compact': compact, 'assistant_html': assistant_html}
        if session:
            resp['session_id'] = session.id
        return JsonResponse(resp)
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def analyze_email(request):
    """AJAX endpoint: passive email analysis.
    Expects POST with optional headers prefixed (e.g., header_From) and 'body' param.
    """
    if request.method != 'POST' or not (request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'):
        return JsonResponse({'ok': False, 'error': 'AJAX POST required'}, status=400)

    # collect some common headers from POST (allow header_From, header_Reply-To, etc.)
    headers = {}
    for k, v in request.POST.items():
        if k.startswith('header_'):
            hdr_name = k[len('header_'):]
            headers[hdr_name] = v

    body = request.POST.get('body', '')
    result = tools.analyze_email(headers, body)
    return JsonResponse({'ok': True, 'data': result})


def history_list(request):
    """Return a list of recent chat sessions (AJAX)"""
    if request.method != 'GET' or not (request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'):
        return JsonResponse({'ok': False, 'error': 'AJAX GET required'}, status=400)

    sessions = ChatSession.objects.order_by('-created_at')[:50]
    data = []
    for s in sessions:
        data.append({'id': s.id, 'title': s.title, 'created_at': s.created_at.isoformat()})
    return JsonResponse({'ok': True, 'data': data})


def history_load(request, session_id):
    """Return messages for a session (AJAX GET)"""
    if request.method != 'GET' or not (request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'):
        return JsonResponse({'ok': False, 'error': 'AJAX GET required'}, status=400)

    try:
        session = ChatSession.objects.get(pk=session_id)
    except ChatSession.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'session not found'}, status=404)

    messages_qs = session.messages.order_by('created_at')
    msgs = [{'role': m.role, 'content': m.content, 'created_at': m.created_at.isoformat()} for m in messages_qs]
    return JsonResponse({'ok': True, 'data': {'session': {'id': session.id, 'title': session.title, 'created_at': session.created_at.isoformat()}, 'messages': msgs}})



