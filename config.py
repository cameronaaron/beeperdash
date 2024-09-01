import os

GITHUB_REPOS = {
    "discordgo": "mautrix/discord",
    "facebookgo": "mautrix/meta",
    "gmessages": "mautrix/gmessages",
    "googlechat": "mautrix/googlechat",
    "instagramgo": "mautrix/meta",
    "linkedin": "beeper/linkedin",
    "signal": "mautrix/signal",
    "slackgo": "mautrix/slack",
    "telegram": "mautrix/telegram",
    "twitter": "mautrix/twitter",
    "whatsapp": "mautrix/whatsapp",
    "hungryserv": "beeper/hungryserv",
    "asmux": "beeper/asmux",
    "gvoice": "mautrix/gvoice",
    "imessage": "mautrix/imessage",
    "imessagego": "beeper/imessagego",
    "heisenbridge": "hifi/heisenbridge",
}

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BEEPER_API_URL = "https://api.beeper.com"
MATRIX_API_URL = "https://matrix.beeper.com"