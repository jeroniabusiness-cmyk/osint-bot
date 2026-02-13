from keep_alive import keep_alive
import logging
import os
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from PIL import Image
from PIL.ExifTags import TAGS
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters

# 1. Setup Logging (Taaki pata chale agar bot fail ho raha hai)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# 2. Start Command (/start)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user.first_name
    await update.message.reply_text(
        f"🕵️‍♂️ Hello {user}! Main OSINT Bot hoon.\n\n"
        "Commands:\n"
        "/ip [IP Address] - IP ki location nikalein\n"
        "/phone [Number] - Number ki info (C-Trace Lite)\n"
        "/user [Name] - Social Media Username check"
    )


# Simple text handler for testing: replies with received text
async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message and update.message.text:
        await update.message.reply_text(f"Received: {update.message.text}")


# IP lookup command
async def ip_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Check agar user ne IP diya hai (e.g., /ip 1.1.1.1)
        if not context.args:
            await update.message.reply_text("❌ Usage: /ip <address>\nExample: /ip 8.8.8.8")
            return

        ip = context.args[0]
        await update.message.reply_text("🔍 IP Scan kar raha hoon...")

        # API Request
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,mobile,proxy,hosting,query"
        response = requests.get(url, timeout=10).json()

        if response.get('status') == 'success':
            # Data Format
            text = (
                f"📡 **IP Intelligence Report**\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🌍 **IP:** `{response.get('query')}`\n"
                f"🏳️ **Country:** {response.get('country')}\n"
                f"🏙️ **City:** {response.get('city')}\n"
                f"🏢 **ISP:** {response.get('isp')}\n"
                f"📱 **Mobile Data:** {'Yes' if response.get('mobile') else 'No'}\n"
                f"☁️ **Hosting/VPN:** {'Yes' if response.get('hosting') else 'No'}"
            )
            await update.message.reply_text(text, parse_mode='Markdown')
        else:
            msg = response.get('message', 'Invalid IP Address.')
            await update.message.reply_text(f"❌ {msg}")
            
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")


# Phone OSINT command
async def phone_osint(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /phone +919876543210 (Country code zaroori hai)")
        return

    number_input = context.args[0]
    try:
        parsed_number = phonenumbers.parse(number_input)
        if not phonenumbers.is_valid_number(parsed_number):
            await update.message.reply_text("❌ Ye number valid nahi lag raha.")
            return

        region = geocoder.description_for_number(parsed_number, "en")
        sim_provider = carrier.name_for_number(parsed_number, "en")
        time_zones = timezone.time_zones_for_number(parsed_number)

        report = (
            f"📱 **Phone Number OSINT**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📞 **Number:** `{number_input}`\n"
            f"📍 **Region:** {region}\n"
            f"🏢 **Carrier (Sim):** {sim_provider}\n"
            f"🕒 **Timezone:** {time_zones}\n"
            f"⚠️ *Note: Live location police ke paas hoti hai, ye registered info hai.*"
        )
        await update.message.reply_text(report, parse_mode='Markdown')

    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


# Rich tools command: returns curated OSINT / manual-recon links
async def tools(update: Update, context: ContextTypes.DEFAULT_TYPE):
    links = (
        "🛠️ **OSINT Toolkit & Hidden Links**\n\n"
        "1. **HaveIBeenPwned:** Check leaked emails\n"
        "   https://haveibeenpwned.com/\n\n"
        "2. **Shodan:** IoT Search Engine (Cameras/Servers)\n"
        "   https://www.shodan.io/\n\n"
        "3. **Wayback Machine:** Deleted websites dekhein\n"
        "   https://web.archive.org/\n\n"
        "4. **OSINT Framework:** Best collection of tools\n"
        "   https://osintframework.com/\n\n"
        "Use these responsibly — do not attempt unauthorized access."
    )
    await update.message.reply_text(links, disable_web_page_preview=True)


async def osint_sites(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🌐 **Top OSINT Websites (Reference):**\n\n"
        "1. **OSINT Framework:** https://osintframework.com/\n"
        "2. **Shodan (IoT Search):** https://www.shodan.io/\n"
        "3. **IntelX (Data Leaks):** https://intelx.io/\n"
        "4. **Social Searcher:** https://www.social-searcher.com/\n"
        "5. **Maltego:** https://www.maltego.com/\n"
        "6. **SearchCode:** https://searchcode.com/\n"
    )
    await update.message.reply_text(msg, disable_web_page_preview=True)


async def check_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /user [username]\nExample: /user technical_yogi")
        return

    username = context.args[0]
    await update.message.reply_text(f"🕵️‍♂️ Checking '{username}' on popular platforms...")

    sites = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/"
    }

    found_text = f"🔍 **Results for {username}:**\n"
    headers = {"User-Agent": "Mozilla/5.0"}

    for name, url in sites.items():
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                found_text += f"✅ **{name}:** Found! {url}\n"
            else:
                found_text += f"❌ **{name}:** Not Found\n"
        except Exception:
            found_text += f"⚠️ **{name}:** Error checking\n"

    social_searcher_link = f"https://www.social-searcher.com/social-buzz/?q5={username}"
    found_text += f"\n🚀 **Deep Scan (Recommended):**\n{social_searcher_link}"

    await update.message.reply_text(found_text, disable_web_page_preview=True)


async def image_analysis(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Support both photos and documents
    if not update.message:
        return

    file_obj = None
    if update.message.photo:
        file_obj = await update.message.photo[-1].get_file()
    elif update.message.document:
        file_obj = await update.message.document.get_file()
    else:
        await update.message.reply_text("Send an image file or photo for analysis.")
        return

    path = "temp_image.jpg"
    await file_obj.download_to_drive(path)

    try:
        image = Image.open(path)
        exif_data = image.getexif()

        report = "🖼️ **Image Metadata Found:**\n\n"
        found = False

        if exif_data:
            for tag_id in exif_data:
                tag = TAGS.get(tag_id, tag_id)
                data = exif_data.get(tag_id)
                if isinstance(data, bytes):
                    try:
                        data = data.decode()
                    except:
                        data = "[Binary Data]"
                report += f"🔹 **{tag}:** {data}\n"
                found = True

        if not found:
            report += "❌ Koi hidden metadata nahi mila. (Image shayad WhatsApp/FB se li gayi hai jahan data strip ho jata hai)."

        await update.message.reply_text(report[:4000])
    except Exception as e:
        await update.message.reply_text(f"Error reading image: {e}")

# 3. Main Execution
if __name__ == '__main__':
    # TOKEN should be provided via the TELEGRAM_TOKEN environment variable
    TOKEN = os.environ.get('TELEGRAM_TOKEN')
    if not TOKEN:
        print('ERROR: TELEGRAM_TOKEN environment variable not set. Set it and rerun.')
        raise SystemExit(1)

    app = ApplicationBuilder().token(TOKEN).build()

    # Handlers (Jo commands sunenge)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("ip", ip_info))
    app.add_handler(CommandHandler("phone", phone_osint))
    app.add_handler(CommandHandler("tools", tools))
    app.add_handler(CommandHandler("user", check_username))
    app.add_handler(CommandHandler("sites", osint_sites))
    app.add_handler(CommandHandler("osint_sites", osint_sites))
    # Add handlers for images/files and echo handler for plain text
    app.add_handler(MessageHandler((filters.PHOTO | filters.Document.ALL), image_analysis))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
    
    # Start keep-alive thread (useful for hosting platforms)
    keep_alive()

    print("Bot is running... (Ctrl+C to stop)")
    app.run_polling()