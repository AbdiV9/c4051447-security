
import bleach

# Whitelist for HTML
ALLOWED_TAGS = ["b", "i", "u", "em", "strong", "a", "p", "ul", "ol", "li", "br"]
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"]
}



from email_validator import validate_email, EmailNotValidError

def validate_username(value: str) -> str:
    if value is None:
        raise ValueError("Email is required.")
    value = value.strip()
    if not value:
        raise ValueError("Email is required.")

    try:
        # Correct: call validate_email(), not validate_username()
        v = validate_email(value, check_deliverability=False)
        return v.email
    except EmailNotValidError as e:
        raise ValueError(str(e))



def validate_string(value: str, field: str, min_len: int = 1, max_len: int = 255) -> str:
    if value is None:
        raise ValueError(f"{field} is required.")
    value = value.strip()
    if len(value) < min_len:
        raise ValueError(f"{field} must be at least {min_len} characters long.")
    if len(value) > max_len:
        raise ValueError(f"{field} must be at most {max_len} characters long.")
    return value


def validate_role(value:str) -> str:
    allowed_values = ["user", "moderator", "admin"]
    if value is None:
        return "user"
    value = value.strip().lower()
    if value not in allowed_values:
        raise ValueError(f"{value} is not one of the allowed values")
    return value

def sanitise_html(value: str, max_len: int = 500) -> str:
    if value is None:
        return ""
    value = value.strip()
    if len(value) > max_len:
        value = value[:max_len]




    cleaned = bleach.clean(
        value,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip = True,
    )
    return cleaned