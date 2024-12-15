import markdown
import bleach

def sanitize_markdown(content):
    """
    Convert Markdown to HTML and sanitize the HTML.
    """
    # Convert Markdown to HTML
    rendered_html = markdown.markdown(content)

    # Allowed HTML tags, attributes, and styles
    allowed_tags = [
        'p', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br',
        'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code',
        'pre', 'hr'
    ]
    allowed_attrs = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title'],
    }
    allowed_styles = []  # Define any allowed styles if necessary

    # Sanitize the HTML
    safe_html = bleach.clean(
        rendered_html,
        tags=allowed_tags,
        attributes=allowed_attrs,
    )

    return safe_html