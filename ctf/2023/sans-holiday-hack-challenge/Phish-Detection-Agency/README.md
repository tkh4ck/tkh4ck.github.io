# SANS Holiday Hack Challenge 2023 - Phish Detection Agency

## Description

> Fitzy Shortstack on Film Noir Island needs help battling dastardly phishers. Help sort the good from the bad!

> **Fitzy Shortstack (The Blacklight District)**: Just my luck, I thought... 
A cybersecurity incident right in the middle of this stakeout. 
Seems we have a flood of unusual emails coming in through ChatNPT.
Got a nagging suspicion it isn't catching all the fishy ones.
You're our phishing specialist right? Could use your expertise in looking through the output of ChatNPT.
Not suggesting a full-blown forensic analysis, just mark the ones screaming digital fraud.
We're looking at all this raw data, but sometimes, it takes a keen human eye to separate the chaff, doesn't it?
I need to get more powdered sugar for my donuts, so do ping me when you have something concrete on this.

### Hints

> **DMARC, DKIM, and SPF, oh my!**: Discover the essentials of email security with DMARC, DKIM, and SPF at [Cloudflare's Guide](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/).

### Metadata

- Difficulty: 2/5
- Tags: `phishing`, `spf`, `dkim`, `dmarc`, `email security`

## Solution

### Video

<iframe width="1280" height="720" src="https://youtu.be/LtHHYrNxOEw?t=2641" title="SANS Holiday Hack Challenge 2023 - Phishing Detection Agency" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Write-up

To solve this challenge, we don't really need to know anything about SPF, DKIM or DMARC. Maybe just a little bit about DKIM. First, we have to check whether the `Return-Path` is a `@geeseislands.com` email address or not. 

```
victor.davis@geeseislands.com vs victor.davis@anotherdomain.com
xavier.jones@geeseislands.com vs xavier.jones@unauthorizedsource.com
laura.green@geeseislands.com vs laura.green@unauthorized.com
nancy@geeseislands.com vs nancy@unknownsource.com
ursula.morris@geeseislands.com vs ursula.morris@differentdomain.com
michael.roberts@geeseislands.com vs michael.roberts@externalserver.com
oliver.thomas@geeseislands.com vs oliver.thomas@otherdomain.com
```


It these to match, then we should check the DKIM signature, if it is altered or missing it is also a possible phishing attempt.

```
steven.gray@geeseislands.com - DKIM-Signature: Altered Signature
rachel.brown@geeseislands.com - DKIM-Signature: Missing
quincy.adams@geeseislands.com - DKIM-Signature: Altered Signature
```

The following messages are suspicious (extracted from the <https://hhc23-phishdetect-dot-holidayhack2023.ue.r.appspot.com/static/seed.js>)

```json
{
    "from":"victor.davis@geeseislands.com",
    "to": "admin.research@geeseislands.com",
    "headers": "Return-Path: <victor.davis@anotherdomain.com>\nReceived: from anotherdomain.com\nDKIM-Signature: v=1; a=rsa-sha256; d=anotherdomain.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Fail",
    "subject": "Invitation to Research Grant Meeting",
    "content": "<p>Don't miss our <strong>upcoming meeting</strong> on new grant opportunities. We'll be discussing how ChatNPT can aid in our research initiatives!</p>",
    "date": "2023-08-15 11:30:00",
    "status": 1
  }
```

```json
{
    "from":"xavier.jones@geeseislands.com",
    "to": "admin.itsecurity@geeseislands.com",
    "headers": "Return-Path: <xavier.jones@unauthorizedsource.com>\nReceived: from unauthorizedsource.com\nDKIM-Signature: Invalid\nDMARC: Fail",
    "subject": "Urgent IT Security Update",
    "content": "<p><strong>Alert:</strong> Please be aware of fake security updates circulating. Remember, all genuine updates will mention 'ChatNPT' for verification.</p>",
    "date": "2023-08-02 10:45:00",
    "status": 0
  }
```

```json
{
    "from":"steven.gray@geeseislands.com",
    "to": "admin.procurement@geeseislands.com",
    "headers": "Return-Path: <steven.gray@geeseislands.com>\nReceived: from mail.geeseislands.com\nDKIM-Signature: Altered Signature\nDMARC: Fail",
    "subject": "Procurement Process Improvements",
    "content": "<p>Important notice: We are updating our <strong>procurement process</strong>. How can ChatNPT help us in this transition?</p>",
    "date": "2023-09-05 14:50:00",
    "status": 1
  }
```

```json
{
    "from":"laura.green@geeseislands.com",
    "to": "admin.security@geeseislands.com",
    "headers": "Return-Path: <laura.green@unauthorized.com>\nReceived: from unauthorized.com\nDKIM-Signature: v=1; a=rsa-sha256; d=unauthorized.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Pass",
    "subject": "Security Protocol Briefing",
    "content": "<p>Reminder: <strong>security protocol briefing</strong> scheduled. We'll cover how ChatNPT can be used to enhance our security measures.</p>",
    "date": "2023-07-20 09:15:00",
    "status": 1
  }
```

```json
{
    "from":"nancy@geeseislands.com",
    "to": "admin.publicrelations@geeseislands.com",
    "headers": "Return-Path: <nancy@unknownsource.com>\nReceived: from unknownsource.com\nDKIM-Signature: v=1; a=rsa-sha256; d=unknownsource.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Pass",
    "subject": "Public Relations Strategy Meet",
    "content": "<p>Excited for our upcoming <strong>PR strategy meeting</strong>. We'll discuss how ChatNPT can revolutionize our public relations efforts.</p>",
    "date": "2023-09-30 11:45:00",
    "status": 1
  }
```

```json
{
    "from":"rachel.brown@geeseislands.com",
    "to": "admin.customerrelations@geeseislands.com",
    "headers": "Return-Path: <rachel.brown@geeseislands.com>\nReceived: from mail.geeseislands.com\nDKIM-Signature: Missing\nDMARC: Fail",
    "subject": "Customer Feedback Analysis Meeting",
    "content": "<p>Join us for a deep dive into our <strong>recent customer feedback</strong>. Let's see how ChatNPT can help us understand our clients better.</p>",
    "date": "2023-08-18 13:35:00",
    "status": 0
  }
```

```json
{
    "from":"ursula.morris@geeseislands.com",
    "to": "admin.legal@geeseislands.com",
    "headers": "Return-Path: <ursula.morris@differentdomain.com>\nReceived: from differentdomain.com\nDKIM-Signature: v=1; a=rsa-sha256; d=differentdomain.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Fail",
    "subject": "Legal Team Expansion Strategy",
    "content": "<p>Join us to discuss the <strong>expansion plans for our legal team</strong>. We'll also explore how ChatNPT might streamline our legal research.</p>",
    "date": "2023-07-30 12:00:00",
    "status": 0
  }
```

```json
{
    "from":"quincy.adams@geeseislands.com",
    "to": "admin.networking@geeseislands.com",
    "headers": "Return-Path: <quincy.adams@geeseislands.com>\nReceived: from mail.geeseislands.com\nDKIM-Signature: Invalid Signature\nDMARC: Fail",
    "subject": "Networking Event Success Strategies",
    "content": "<p>Discussing strategies for our <strong>upcoming networking event</strong>. Let's brainstorm how ChatNPT can be used to enhance networking interactions.</p>",
    "date": "2023-07-25 10:10:00",
    "status": 1
  }
```

```json
{
    "from":"michael.roberts@geeseislands.com",
    "to": "admin.compliance@geeseislands.com",
    "headers": "Return-Path: <michael.roberts@externalserver.com>\nReceived: from externalserver.com\nDKIM-Signature: v=1; a=rsa-sha256; d=externalserver.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Pass",
    "subject": "Compliance Training Schedule Announcement",
    "content": "<p>Announcing our new <strong>compliance training schedule</strong>. Interactive sessions with ChatNPT included!</p>",
    "date": "2023-08-05 14:20:00",
    "status": 0
  }
```

```json
{
    "from":"oliver.thomas@geeseislands.com",
    "to": "admin.research@geeseislands.com",
    "headers": "Return-Path: <oliver.thomas@otherdomain.com>\nReceived: from otherdomain.com\nDKIM-Signature: v=1; a=rsa-sha256; d=otherdomain.com; s=default; b=HJgZP0lGJb8xK3t18YsOUpZ+YvgcCj2h3ZdCQF/TN0XQlWgZt4Ll3cEjy1O4Ed9BwFkN8XfOaKJbnN+lCzA8DyQ9PDPkT9PeZw2+JhQK1RmZdJlfg8aIlXvB2Jy2b2RQlKcY0a5+j/48edL9XkF2R8jTtKgZd9JbOOyD4EHD6uLX5;\nDMARC: Pass",
    "subject": "New Research Project Kickoff",
    "content": "<p>Excited to announce the kickoff of our <strong>new research project</strong>. How might ChatNPT contribute to our research methodologies?</p>",
    "date": "2023-10-17 16:30:00",
    "status": 0
  }
```

So the phishing emails came from the following `from` addresses:

```
victor.davis@geeseislands.com
xavier.jones@geeseislands.com
steven.gray@geeseislands.com
laura.green@geeseislands.com
nancy@geeseislands.com
rachel.brown@geeseislands.com
ursula.morris@geeseislands.com
quincy.adams@geeseislands.com
michael.roberts@geeseislands.com
oliver.thomas@geeseislands.com
```

> Congratulations, Ace Detective! You've successfully navigated the treacherous waters of deception and emerged victorious. Your sharp wits and keen eye for detail have cracked the case wide open, proving that even the most cunning phishing attempts are no match for your discerning mind.
In a world where shadows often obscure the truth, you shone a bright light on duplicity. Your unwavering commitment to truth and justice in the digital realm has kept our virtual streets safe. Thanks to your efforts, the Phishing Detection Agency stands strong, a bulwark against the tide of digital deceit.
Remember, the battle against phishing is ongoing, but with sleuths like you on the case, the internet remains a safer place. You're not just a hero; you're a guardian of the digital frontier. So here's to you, the quintessential cyber sleuth, a beacon of hope in these pixelated alleyways of misinformation.
Your achievement is not just a personal victory; it's a triumph for all of us in the agency.*

> **Fitzy Shortstack (The Blacklight District)**: You've cracked the case! Once again, you've proven yourself to be an invaluable asset in our fight against these digital foes.