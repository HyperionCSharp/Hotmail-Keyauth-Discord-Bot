# Discord Bot with Microsoft Login Checker

This Discord bot allows users to redeem license keys, verify their accounts, and check email:password combinations against Microsoft's authentication process. The bot is powered by Python/Discord.py and utilizes the KeyAuth API for license management.

I changed the keyauth file to only take what was needed like license auth, and username, it logs the account id of the discord user and matches it with the license in the redeemed file.

This bot has issues with proxies, so it is recommended to use a proxyless mode.
FEEL FREE TO USE THIS BOT, BUT PLEASE CREDIT ME IF YOU DO.
I WANT TO SEE WHAT OTHERS CAN MAKE OF THIS BOT.

THIS IS TO BE USED FOR EDUCATIONAL PURPOSES ONLY. I AM NOT RESPONSIBLE FOR ANYTHING YOU DO WITH THIS BOT.

## Features

- **License Redemption**: Users can redeem their license keys and gain access to premium features.
- **Microsoft Login Checking**: Check the validity of email:password combos using Microsoft's login API.
- **Proxy Support**: Supports HTTP, SOCKS4, and SOCKS5 proxies for login checks.
- **Real-Time Notifications**: The bot sends real-time updates on the status of the checking process.
- **Role Assignment**: Users who redeem a license key are automatically assigned a role on the Discord server.

## Commands

- `.redeem <license_key>` - Redeem a license key.
- `.login` - Verify your license key.
- `.check [no = proxyless / yes = use proxies]` - Check a combo file.
- `.stop` - Stop the current checking process.
- `.helpme` - Display help information.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/HyperionCSharp/Hotmail-Keyauth-Discord-Bot.git
   cd repository
   ```


