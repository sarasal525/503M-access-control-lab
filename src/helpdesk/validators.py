# validators.py
#
# validators for file uploads, etc.

from django.utils.translation import gettext as _

from helpdesk import settings as helpdesk_settings

# TODO: can we use the builtin Django validator instead?
# see:
# https://docs.djangoproject.com/en/4.0/ref/validators/#fileextensionvalidator

# Magic bytes every real file of that type starts with. The claimed
# extension and Content-Type are never enough on their own -- an attacker
# can set both to whatever they want, so the actual bytes are what we trust.
IMAGE_MAGIC_BYTES = {
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
}


def validate_file_extension(value):
    import os

    from django.core.exceptions import ValidationError

    ext = os.path.splitext(value.name)[1]  # [0] returns path+filename
    # TODO: we might improve this with more thorough checks of file types
    # rather than just the extensions.

    if not helpdesk_settings.HELPDESK_VALIDATE_ATTACHMENT_TYPES:
        return

    # Reject double extensions outright (e.g. shell.php.png), since a
    # naive check that only looks at the final extension would be fooled.
    if value.name.count(".") > 1:
        raise ValidationError(_("Filenames with multiple extensions are not allowed."))

    ext_lower = ext.lower()

    # TODO: one more check in case it is a file with no extension; we
    # should always allow that?
    if ext_lower not in helpdesk_settings.HELPDESK_VALID_EXTENSIONS and not (
        ext_lower == "" or ext_lower == "."
    ):
        raise ValidationError(_("Unsupported file extension: ") + ext_lower)

    # For image extensions, confirm the actual bytes match the claimed
    # type instead of trusting the extension or the declared Content-Type.
    if ext_lower in IMAGE_MAGIC_BYTES:
        value.seek(0)
        header = value.read(16)
        value.seek(0)
        if not any(header.startswith(sig) for sig in IMAGE_MAGIC_BYTES[ext_lower]):
            raise ValidationError(
                _("File content does not match its extension: ") + ext_lower
            )