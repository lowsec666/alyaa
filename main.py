import discord
from discord.ext import commands
import youtube_dl
import requests
import openai

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

openai.api_key = 'sk-None-9OeepaBhogdFaOR5JhAmT3BlbkFJGtGXaAdqfv2SgnGagUT8'  # Ganti dengan OpenAI API Key Anda

@bot.event
async def on_ready():
    print(f'We have logged in as {bot.user}')

@bot.command()
async def join(ctx):
    """Command to make the bot join the voice channel."""
    if ctx.author.voice:
        channel = ctx.author.voice.channel
        await channel.connect()
        await ctx.send(f"Joined {channel}")
    else:
        await ctx.send("You are not connected to a voice channel.")

@bot.command()
async def leave(ctx):
    """Command to make the bot leave the voice channel."""
    if ctx.voice_client:
        await ctx.voice_client.disconnect()
        await ctx.send("Left the voice channel.")
    else:
        await ctx.send("I'm not in a voice channel.")

@bot.command()
async def play(ctx):
    """Command to play 'Night Changes' by One Direction."""
    if ctx.voice_client:
        ydl_opts = {
            'format': 'bestaudio/best',
            'postprocessors': [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }],
            'outtmpl': 'downloads/%(title)s.%(ext)s',
            'noplaylist': True,
        }
        
        url = 'https://youtu.be/syFZfO_wfMQ?si=gJsWPOJVByhCaAsD'  # URL untuk "Night Changes"
        
        with youtube_dl.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            file = info['title'] + '.' + ydl_opts['postprocessors'][0]['preferredcodec']
        
        ctx.voice_client.stop()
        ctx.voice_client.play(discord.FFmpegPCMAudio(file))
        await ctx.send("Now playing 'Night Changes' by One Direction.")
    else:
        await ctx.send("I'm not connected to a voice channel.")

@bot.command()
async def stop(ctx):
    """Command to stop the current audio."""
    if ctx.voice_client and ctx.voice_client.is_playing():
        ctx.voice_client.stop()
        await ctx.send("Stopped the audio.")
    else:
        await ctx.send("No audio is currently playing.")

@bot.command()
async def securitytips(ctx):
    tips = (
        "**Security Tips:**\n"
        "1. **Keep your software updated**: Always update your operating system and applications to the latest versions to protect against vulnerabilities.\n"
        "2. **Use strong, unique passwords**: Avoid using the same password across multiple sites and use a mix of letters, numbers, and symbols.\n"
        "3. **Enable two-factor authentication (2FA)**: Add an extra layer of security to your accounts by enabling 2FA.\n"
        "4. **Be cautious of phishing attempts**: Do not click on suspicious links or provide personal information to unknown sources.\n"
        "5. **Regularly backup your data**: Keep backups of important data to prevent loss in case of a cyberattack or hardware failure.\n"
        "6. **Use a VPN**: Protect your online activities and data from eavesdropping by using a reliable VPN service.\n"
        "7. **Monitor your accounts**: Regularly check your bank and online accounts for any unauthorized activity."
    )
    await ctx.send(tips)

@bot.command()
async def kali(ctx):
    kali_commands = (
        "**Common Kali Linux Commands:**\n"
        "`nmap` - Network scanner to discover hosts and services. Example: `nmap -sP 192.168.1.0/24`\n"
        "`airmon-ng` - Tool for wireless network scanning and monitoring. Example: `airmon-ng start wlan0`\n"
        "`aircrack-ng` - Tool for cracking WEP and WPA/WPA2 encryption. Example: `aircrack-ng capture.cap`\n"
        "`metasploit` - Penetration testing framework. Example: `msfconsole`\n"
        "`burpsuite` - Web vulnerability scanner and analysis tool. Example: `burpsuite`\n"
        "`hydra` - Fast network logon cracker. Example: `hydra -l admin -P passwords.txt ftp://192.168.1.100`\n"
        "`wireshark` - Network protocol analyzer. Example: `wireshark`\n"
        "`john` - Password cracking tool. Example: `john --wordlist=passwords.txt hashes.txt`\n"
        "`nikto` - Web server scanner. Example: `nikto -h http://example.com`\n"
        "`tcpdump` - Network packet analyzer. Example: `tcpdump -i eth0`\n"
        "`social-engineer-toolkit` - Tool for social engineering attacks. Example: `setoolkit`\n"
        "`sqlninja` - SQL injection tool for Microsoft SQL Server. Example: `sqlninja -u <url>`\n"
        "`netcat` - Network utility for reading and writing data across network connections. Example: `nc -lvp 4444`\n"
        "`dirb` - Web directory brute-forcing tool. Example: `dirb http://example.com`\n"
        "`wpscan` - WordPress vulnerability scanner. Example: `wpscan --url http://example.com`\n"
        "`enum4linux` - Enumeration tool for Linux systems. Example: `enum4linux -a <IP>`\n"
        "`recon-ng` - Web reconnaissance framework. Example: `recon-ng`\n"
        "`searchsploit` - Exploit database search tool. Example: `searchsploit <exploit-name>`"
    )
    await ctx.send(kali_commands)

@bot.command()
async def sqlmap(ctx):
    sqlmap_commands = (
        "**Common SQLmap Commands:**\n"
        "`sqlmap -u <url> --dbs` - Enumerate databases.\n"
        "`sqlmap -u <url> -D <database> --tables` - List tables in a database.\n"
        "`sqlmap -u <url> -D <database> -T <table> --columns` - List columns in a table.\n"
        "`sqlmap -u <url> -D <database> -T <table> -C <column> --dump` - Dump data from a column.\n"
        "`sqlmap -u <url> --risk=3 --level=5` - Perform a more comprehensive scan.\n"
        "`sqlmap -u <url> --os-shell` - Attempt to get an OS shell.\n"
        "`sqlmap -u <url> --threads=<number>` - Set the number of threads for the scan.\n"
        "`sqlmap -u <url> --batch` - Run sqlmap in batch mode without user interaction.\n"
        "`sqlmap -u <url> --cookie=<cookie>` - Use specified cookies for authentication.\n"
        "`sqlmap -u <url> --proxy=<proxy>` - Use specified proxy server."
    )
    await ctx.send(sqlmap_commands)

@bot.command()
async def tools(ctx):
    tools_info = (
        "**Security Tools and Their Uses:**\n"
        "`nmap` - Network discovery and security auditing.\n"
        "`aircrack-ng` - Wireless network security auditing.\n"
        "`metasploit` - Framework for penetration testing.\n"
        "`burpsuite` - Web vulnerability scanner.\n"
        "`sqlmap` - Automated SQL injection tool.\n"
        "`wireshark` - Network protocol analyzer.\n"
        "`john` - Password cracking.\n"
        "`hydra` - Network logon cracker.\n"
        "`nikto` - Web server scanner for vulnerabilities.\n"
        "`tcpdump` - Network packet analyzer.\n"
        "`social-engineer-toolkit` - Tool for social engineering attacks.\n"
        "`sqlninja` - SQL injection tool for Microsoft SQL Server.\n"
        "`netcat` - Network utility for reading and writing data.\n"
        "`dirb` - Web directory brute-forcing tool.\n"
        "`wpscan` - WordPress vulnerability scanner.\n"
        "`enum4linux` - Enumeration tool for Linux systems.\n"
        "`recon-ng` - Web reconnaissance framework.\n"
        "`searchsploit` - Exploit database search tool."
    )
    await ctx.send(tools_info)

@bot.command()
async def resources(ctx):
    resources_list = (
        "**Learning Resources for Cybersecurity:**\n"
        "1. **OWASP**: [owasp.org](https://owasp.org)\n"
        "2. **Cybrary**: [cybrary.it](https://www.cybrary.it)\n"
        "3. **SANS Institute**: [sans.org](https://www.sans.org)\n"
        "4. **Coursera Cybersecurity Courses**: [coursera.org](https://www.coursera.org)\n"
        "5. **edX Cybersecurity Courses**: [edx.org](https://www.edx.org)\n"
        "6. **Infosec Institute**: [infosecinstitute.com](https://www.infosecinstitute.com)\n"
        "7. **SecurityTube**: [securitytube.net](https://www.securitytube.net)\n"
        "8. **Khan Academy Computing**: [khanacademy.org](https://www.khanacademy.org/computing)\n"
        "9. **Udemy Cybersecurity Courses**: [udemy.com](https://www.udemy.com)\n"
        "10. **PluralSight**: [pluralsight.com](https://www.pluralsight.com)"
    )
    await ctx.send(resources_list)

@bot.command()
async def pentest(ctx):
    pentest_guide = (
        "**Penetration Testing Guide:**\n"
        "1. **Reconnaissance**: Gather information about the target (e.g., using `nmap` or `whois`).\n"
        "2. **Scanning**: Identify open ports and services (e.g., using `nmap` or `netcat`).\n"
        "3. **Enumeration**: Find vulnerabilities and gather more detailed information (e.g., using `enum4linux` or `nikto`).\n"
        "4. **Exploitation**: Attempt to exploit identified vulnerabilities (e.g., using `metasploit` or `sqlmap`).\n"
        "5. **Post-Exploitation**: Maintain access and gather further information (e.g., using `meterpreter` or `netcat`).\n"
        "6. **Reporting**: Document findings and provide recommendations.\n"
        "7. **Cleanup**: Remove any changes made during the test."
    )
    await ctx.send(pentest_guide)

@bot.command()
async def cryptotools(ctx):
    crypto_tools = (
        "**Crypto Tools and Techniques:**\n"
        "`openssl` - Toolkit for SSL/TLS and general-purpose cryptography. Example: `openssl enc -aes-256-cbc -in file.txt -out file.enc`\n"
        "`gpg` - Encryption tool for secure communication. Example: `gpg --encrypt --recipient <recipient> file.txt`\n"
        "`hashcat` - Password recovery tool using various hash algorithms. Example: `hashcat -m 0 hash.txt wordlist.txt`\n"
        "`John the Ripper` - Password cracking tool. Example: `john --wordlist=passwords.txt hashes.txt`\n"
        "`Cryptsetup` - Disk encryption tool. Example: `cryptsetup luksFormat /dev/sdX`\n"
        "`TrueCrypt` - Disk encryption tool (legacy). Example: `truecrypt /path/to/container`\n"
        "`openssl` - Command-line tool for managing certificates and keys. Example: `openssl x509 -in cert.pem -text -noout`"
    )
    await ctx.send(crypto_tools)

@bot.command()
async def securitynews(ctx):
    try:
        response = requests.get('https://newsapi.org/v2/top-headlines', params={
            'apiKey': '80da55ff49204423a7fa3c1b76961f37',  # Ganti dengan API Key Anda
            'category': 'technology',
            'q': 'cybersecurity',
            'pageSize': 5
        })
        data = response.json()
        articles = data.get('articles', [])
        if not articles:
            await ctx.send("No recent security news found.")
        else:
            news = "**Latest Security News:**\n"
            for article in articles:
                news += f"- [{article['title']}]({article['url']})\n"
            await ctx.send(news)
    except Exception as e:
        await ctx.send(f"An error occurred while fetching news: {e}")

@bot.command()
async def support(ctx):
    support_info = (
        "**Support Information:**\n"
        "For assistance, please refer to the following resources:\n"
        "1. **Help Center**: [Help Center Link](https://example.com/help)\n"
        "2. **FAQ**: [Frequently Asked Questions](https://example.com/faq)\n"
        "3. **Contact Us**: You can contact us directly via email at [support@example.com](mailto:support@example.com)\n"
        "4. **Community Forum**: Join our community forum for discussions and support: [Community Forum Link](https://example.com/forum)\n"
        "5. **Documentation**: Access the full documentation here: [Documentation Link](https://example.com/docs)\n"
        "6. **Report an Issue**: If you encounter any issues, report them using this [form](https://example.com/report)\n"
        "7. **Live Chat**: For real-time assistance, visit our [Live Chat](https://example.com/livechat) during business hours."
    )
    await ctx.send(support_info)

@bot.command()
async def emergency(ctx):
    emergency_info = (
        "**Emergency Information:**\n"
        "If you require immediate assistance, please follow these steps:\n"
        "1. **Contact Emergency Services**: Call your local emergency services (e.g., 911 in the US).\n"
        "2. **Report the Incident**: Provide as much detail as possible about the situation to emergency responders.\n"
        "3. **Follow Safety Protocols**: Follow any instructions given by emergency personnel.\n"
        "4. **Notify Relevant Authorities**: If the situation involves a security breach, notify relevant authorities or IT support.\n"
        "5. **Document the Incident**: Keep a record of what happened and any actions taken."
    )
    await ctx.send(emergency_info)

@bot.command()
async def gpt(ctx, *, prompt):
    try:
        response = openai.Completion.create(
            engine="davinci-codex",
            prompt=prompt,
            max_tokens=150
        )
        answer = response.choices[0].text.strip()
        await ctx.send(answer)
    except Exception as e:
        await ctx.send(f"An error occurred while accessing GPT: {e}")

bot.run('YOUR_BOT_TOKEN')
