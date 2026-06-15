import requests
import email


def follow_redirects(url):

    try:

        response = requests.get(
            url, allow_redirects=True, timeout=10, headers={"User-Agent": "Mozilla/5.0"}
        )

        final_url = response.url

        redirect_chain = [r.url for r in response.history]

        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "redirected": len(redirect_chain) > 0,
            "num_redirects": len(redirect_chain),
        }

    except Exception as e:

        return {
            "original_url": url,
            "final_url": url,
            "redirect_chain": [],
            "redirected": False,
            "error": str(e),
        }


def read_eml_file(file_path):

    with open(file_path, "rb") as f:

        msg = email.message_from_bytes(f.read())

    headers = f"From: {msg.get('From', '')}\n"
    headers += f"Reply-To: {msg.get('Reply-To', '')}\n"
    headers += f"Subject: {msg.get('Subject', '')}\n"
    headers += f"Received: {msg.get('Received', '')}\n"

    body = ""

    if msg.is_multipart():

        for part in msg.walk():

            if part.get_content_type() == "text/plain":

                body += part.get_payload(decode=True).decode(errors="ignore")

    else:

        body = msg.get_payload(decode=True).decode(errors="ignore")

    return headers + "\n" + body
