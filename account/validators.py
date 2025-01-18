from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class PolicyValidator:
    def __init__(self, min_length=10, uppercase=1, numbers=1, special=1, nonletters=1):
        self.min_length = min_length
        self.uppercase = uppercase
        self.numbers = numbers
        self.special = special
        self.nonletters = nonletters

    def validate(self, password, user=None):
        errors = []

        if len(password) < self.min_length:
            errors.append(_("Password must be at least %(min_length)d characters long.") % {'min_length': self.min_length})

        if sum(1 for char in password if char.isupper()) < self.uppercase:
            errors.append(_("Password must contain at least %(count)d uppercase letter(s).") % {'count': self.uppercase})

        if sum(1 for char in password if char.isdigit()) < self.numbers:
            errors.append(_("Password must contain at least %(count)d number(s).") % {'count': self.numbers})

        special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
        if sum(1 for char in password if char in special_chars) < self.special:
            errors.append(_("Password must contain at least %(count)d special character(s).") % {'count': self.special})

        if sum(1 for char in password if not char.isalpha()) < self.nonletters:
            errors.append(_("Password must contain at least %(count)d non-letter character(s).") % {'count': self.nonletters})

        if errors:
            raise ValidationError(errors)
    
    def get_help_text(self):
        """Return the password requirements for display in forms."""
        return _(
            "Your password must be at least %(min_length)d characters long, "
            "contain at least %(uppercase)d uppercase letter(s), "
            "%(numbers)d number(s), %(special)d special character(s), and "
            "%(nonletters)d non-letter character(s)."
        ) % {
            'min_length': self.min_length,
            'uppercase': self.uppercase,
            'numbers': self.numbers,
            'special': self.special,
            'nonletters': self.nonletters
        }

