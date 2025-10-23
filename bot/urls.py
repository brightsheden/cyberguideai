from django.urls import path
from .views import home, analyze_link, analyze_email, history_list, history_load, scan_upload, link_page, email_page


urlpatterns = [
    path("", home, name="homes"),
    path("scan/upload/", scan_upload, name="scan_upload"),
    path("tools/link/", link_page, name="link_page"),
    path("tools/email/", email_page, name="email_page"),
    path("analyze/link/", analyze_link, name="analyze_link"),
    path("analyze/email/", analyze_email, name="analyze_email"),
    path("history/list/", history_list, name="history_list"),
    path("history/load/<int:session_id>/", history_load, name="history_load"),
]
