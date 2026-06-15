import asyncio
from playwright.async_api import async_playwright
import os


async def follow_redirects_browser(url):

    async with async_playwright() as p:

        browser = await p.chromium.launch(headless=True)

        page = await browser.new_page()

        redirect_chain = []

        page.on(
            "response",
            lambda response: (
                redirect_chain.append({"url": response.url, "status": response.status})
                if response.status in [301, 302, 303, 307, 308]
                else None
            ),
        )

        try:

            await page.goto(url, wait_until="networkidle", timeout=30000)

            final_url = page.url

            screenshot_path = f"screenshots/{url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]}.png"

            os.makedirs("screenshots", exist_ok=True)

            await page.screenshot(path=screenshot_path)

        except Exception as e:

            final_url = url

            screenshot_path = None

        await browser.close()

        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "redirected": len(redirect_chain) > 0,
            "num_redirects": len(redirect_chain),
            "screenshot_path": screenshot_path,
        }


def analyze_redirects(url):

    return asyncio.run(follow_redirects_browser(url))
