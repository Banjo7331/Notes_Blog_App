from django import forms

class MarkdownNoteForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'placeholder': 'Enter note title'})
    )
    content = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 10, 'placeholder': 'Write your Markdown note here...'}),
        required=True
    )