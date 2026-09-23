from email import policy
from email.parser import Parser


def parse_email(email_text):
    """
    Parse raw email text and return structured email information.
    """

    msg = Parser(
        policy=policy.default
    ).parsestr(email_text)

    return {
        "from": msg.get("From", "Not found"),
        "to": msg.get("To", "Not found"),
        "subject": msg.get("Subject", "Not found"),
        "date": msg.get("Date", "Not found"),
        "reply_to": msg.get("Reply-To", "Not found"),
        "return_path": msg.get("Return-Path", "Not found"),
        "message_id": msg.get("Message-ID", "Not found"),
        "authentication_results": msg.get(
            "Authentication-Results",
            ""
        ),
    }