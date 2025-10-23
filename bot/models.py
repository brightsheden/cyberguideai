from django.db import models
from django.utils import timezone


# Chat session (one per conversation)
class ChatSession(models.Model):
	title = models.CharField(max_length=200, blank=True)
	created_at = models.DateTimeField(default=timezone.now)

	def __str__(self):
		return self.title or f"Session {self.id} - {self.created_at:%Y-%m-%d %H:%M}"


# Individual messages in a chat session
class ChatMessage(models.Model):
	ROLE_CHOICES = (
		('user', 'User'),
		('assistant', 'Assistant'),
		('system', 'System'),
	)

	session = models.ForeignKey(ChatSession, related_name='messages', on_delete=models.CASCADE)
	role = models.CharField(max_length=16, choices=ROLE_CHOICES)
	content = models.TextField()
	created_at = models.DateTimeField(default=timezone.now)

	class Meta:
		ordering = ['created_at']

	def __str__(self):
		return f"{self.role}: {self.content[:60]}"
