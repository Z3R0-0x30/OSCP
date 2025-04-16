## Machine Information

- **Machine Name:** Dog
- **Machine IP:** 10.10.11.58
- **Machine Difficulty:** Easy
- **Machine OS:** Linux

## Reconnaissance - gathering information

Information gathering is a very crucial step in any kind of hack, and it is performed by all kinds of hackers regardless of what hat they are wearing. In this, we try to collect as much information as possible about the target, so later on we can find a vulnerability to exploit.

### Ports and Services scan

You are given a task to rob a royal palace, but the only information you have is the **address** of the royal palace, what will be your next step? For me it would be walking around the palace to find **open doors & ports**, cause their availability is the greatest reason for their vulnerability. This is what happens in most of the attacks, a computer has a vulnerable or unwanted port open which becomes a perfect gateway for hackers to gain access to the system.

![](images-dog/1.png)

**Command I performed:**
- `sudo nmap -sVC -p- -O 10.10.11.58 | tee nmapDog.txt`

**Understanding the command:**
- **-sVC** - It check for Service version and execute all default NSE scripts corresponding to the services for more information.
- **-p-** - It scan all ports.
- **-O** - It detects possible OS running on the target machine.

I use nmap tool to scan for all TCP open ports with OS detection, and in the result we get 2 ports that are open, which are as follow:
1. 22/tcp - OpenSSH 8.2p1
2. 80/tcp - Apache httpd 2.4.41 (likely vulnerable)
With the Apache service, we found 2 interesting things, which are a robots.txt and a git repository. These two things can be utilized for further investigation and staging our initial exploit.

### Website Recon

In this phase, we will go through target's website and try to gather information that can help us to identify potential vulnerabilities or chances for any exploitation.

![](images-dog/2.png)

![](images-dog/3.png)

As we open the website, we see it is related to Dogs, such as causes of obesity in dogs, dog's diet, lack of exercise, etc. I manually checked all links in the website and they all end up to different webpages with information related to Dogs.

![](images-dog/4.png)

![](images-dog/5.png)

As I was searching through the website, I found a **Powered by Backdrop CMS** line at the bottom of the website, which clarifies that the website is based on Backdrop CMS. I also visited the About page and found a support email, I noted it down thinking it might become useful in future.

![](images-dog/6.png)

![](images-dog/7.png)

Next, I visit the login page and we also see reset portal here. Another interesting thing to explore here is the git repository by appending `/.git/` at the end of your url as shown in the image. I explored it manually and you can also do to get an idea of the structure, but it is not directly related to our Hack The Box task so I would not be adding all those process or findings here.

![](images-dog/9.png)

For investigating publicly accessible git repositories there is a great tool on github, and I would be using it to locally download the git repo and unpacking it for analysis. 

**Commands I performed:**
- `git clone https://github.com/internetwache/GitTools.git`
- `cd GitTools/Dumper`
- `./gitdumper.sh http://10.10.11.58/.git/ ./dog-git`
- `cd ..`
- `cd Extractor`
- `./extractor.sh ../Dumper/dog-git/ dog-ext-git/`

![](images-dog/10.png)

![](images-dog/11.png)

![](images-dog/12.png)

In the GitTools, there is a `gitdumper` command that will create a local directory which will dump all the content of git repo according to the target URL. After that, you will have to use `extractor` command to create another local directory which will take all the dumped data previously created with `gitdumper` and it will extract everything in it. This will allow you to view the content of git repository on your local system.

Next step is to go into the extracted directory and look for valuable information.

![](images-dog/13.png)

![](images-dog/14.png)

![](images-dog/15.png)

I explored almost all files and folders and found many interesting things, which included the following:
1. **hash salt:** There is a variable named hash_salt with a hashed value, it is probably the salt used for passwords.
2. **mysql database path:** We see a mysql database path, which includes a username root and a password BackDropJ2024DS2024.
3. **config dir:** We also found the URL path for the config files (active and staging).
These information can further help us to find more valuable things or maybe even give us access to the admin dashboard.

![](images-dog/16.png)

![](images-dog/16_1.png)

Lastly, I search for meaningful information in the config/active file and found an email address. Considering the fact that we already have found a password, we can try using it with this email to login into the admin portal. There was also core/modules/system directory where we found the exact version of **backdrop** in system.info file.

## Gaining Access

![](images-dog/17.png)

We were successfully able to login into the admin portal using the leaked email and password we found during our analysis, and it is an Admin dashboard which can be further used to exploit the system. The password is comparatively complex than other challenges

> *"A strong password does not always define a secure environment, there are other ways to get in"*

### Searching for available exploits & vulnerabilities

We already have version information which we previously found during our investigation, now we can use it to search for available vulnerabilities and their exploits. I would use a well-known tool `searchsploit` for this job.

**Commands I performed:**
- `searchsploit backdrop 1.27.1`
- `searchsploit -m php/webapps/52021.py`

![](images-dog/18.png)

I searched for available exploits for backdrop 1.27.1, and there was only one exploit available in their database, and it is a Authenticated RCE which means that to execute it the attacker will need to be authenticated. This would work for us because we already are authenticated and RCE seems a good way in. So, I immediately install the exploit in my local system. For now, we will see how the exploit works, a detailed explaination might be launched soon or will be available on my discord server.

### Exploiting the system

**Commands I performed:**
- `python3 52021.py http://10.10.11.58/`
- `tar -czf shell.tar.gz shell`

![](images-dog/19.png)

![](images-dog/19_1.png)

Going through the exploit, it is pretty clear that it generates a evil zip file which can be uploaded on the website to get a reverse shell. The problem with us is that our site only accepts files with **tar.gz** compression, so after generating the evil file we will have to recompress it with tar.gz.

![](images-dog/20.png)

![](images-dog/21.png)

Lastly, we go to the `installer/manual` subdirectory for uploading our malicious file and we were successfully able to upload it. Now it is time to access it, but during this period I realized there was some firewall that immediately deleted our uploaded shell after we executed certain commands, so definitely we cannot use it as a persistent reverse shell. 

**Command I performed (on the shell uploaded):**
- `cat /etc/passwd`

![](images-dog/23.png)

After spending some time I found a way to get inside the system without any trouble. We can expose the `/etc/passwd` file and use the user information of johncusack to get a connection from SSH. We would be using the following credential to login SSH:
- **Username:** johncusack
- **Password:** BackDropJ2024DS2024

**Command I performed:**
- `ssh johncusack@10.10.11.58`

![](images-dog/24.png)

![](images-dog/user_flag.png)

Nice achievement! We were able to successfully login into the user through SSH and a reused password. We also got our first flag, now we will find ways to escalate our privileges.

## Privilege Escalation - root Me Please

Privilege Escalation is a process of elevating your privileges from a normal user to a admin-level or root user. It is used in many challenges, and it is one of the most complex things but also simpler to achieve. The exploits or path way used in privilege escalation can sometimes be difficult to understand, but it is worth giving a shot.

### Searching for loopholes

The first step is to search for gateways that will possibly help you to elevate privileges, it is similar to scanning for available vulnerabilities.

![](images-dog/25.png)

![](images-dog/26.png)

![](images-dog/27.png)

Great! We found a binary that we can execute as johncusack user as root, and we will require password for this (which we already have). On further analysis, I found that there is a way to execute commands using this binary, by using the `--root` and `eval` options.

**Command I performed:**
- `sudo /usr/local/bin/bee --root=/var/www/html/ eval 'system("/bin/bash")'`

![](images-dog/root_flag.png)

Finally we were successfully able to escalate our privileges as root and got the root flag. The detailed explaination for exploits used might be released soon on my discord server, so don't forget to join it.

## Conclusion - lesson learned

Time for concluding everything that we can learn from this vulnerable machine, such as detail on vulnerability or fixes available. For me, the initial foothold was quite difficult as compared to privilege escalation. If there are any other possible ways to exploit the machine then do not hesitate to ping the methodology on my discord server's `HTB` channel by mentioning me.

### Vulnerabilities - what was hacked?

This section will discussion the vulnerabilities that were exploited and used for our benefit to gain access to the system, and it will also include available fixes for those vulnerabilities.

#### Git Repo - exposed to the web

Initially while performing our ports and services scan, we were able to find `.git` repository being exposed to the Internet, it means anyone can use it to extract sensitive information. In most cases, people do not openly share their git repo if it contains some sensitive information, but here it was accessible and it also had sensitive information that helped us to gain our foothold on the system.

##### Fix - what should be done

The best recommended fix is to private the git repository from the github account if it contains any sensitive information, cause github is a place where open-source software are published, and it is by-default publicly accessible. It is better to private it from the setting of the git repository which will avoid any access to it.

### backdrop 1.27.1 - outdated software

After getting the access to the admin's account using the information that was gathered from git repository, we were able to find available exploit for LFI vulnerability in the backdrop 1.27.1 CMS. This vulnerability allow an authenticated user to upload a malicious file which he can execute to get a reverse shell.

##### Fix - what should be done

The best recommended advice is to update backdrop < 1.27.1 or to its latest version. This will get rid of the LFI vulnerability because it is been already patched in the later versions by backdrop. 

This is the end, for my discord server join the following link: [Discord - Cyber X army](https://discord.gg/wyfwSxn3YB)

