# Janus — 10-Minute Presentation Script (Plain-Language Version)

Paced to ~90-135 wpm per section (comfortable talking speed), leaving slack in every demo block for clicks/page loads. Total scripted speech: ~9:20, last 40s open for the first judge question.

| Time | Section |
|---|---|
| 0:00–1:00 | The hook |
| 1:00–2:30 | How we built the data |
| 2:30–4:00 | How the AI works |
| 4:00–5:30 | Demo: compliance check + auto-fix |
| 5:30–7:00 | Demo: AI traffic classification |
| 7:00–8:00 | Demo: compare tunnels + reports |
| 8:00–9:00 | Why it matters |
| 9:00–9:20 | Close |

---

### 1. The Hook (0:00 – 1:00)
*Slide 1 → Slide 2*

> Good morning, judges. We're Team CipherOps, and this is Janus — a tool that checks how safe a VPN connection really is, without ever breaking its encryption.
>
> Here's the problem we're solving. Government and company networks use a tunnel technology called IPsec to keep data private. Two things make it hard to check if that tunnel is actually safe. First, setting it up involves a complicated back-and-forth handshake, and mistakes in that handshake often slip through unnoticed. Second, once the tunnel is running, everything inside is encrypted — you can't look inside without the secret key.
>
> Most AI security tools fake their way around this. They guess what's inside and act confident about it. Janus doesn't do that. We only claim what we can actually prove, and when we're not sure, we say so.

---

### 2. How We Built the Data (1:00 – 2:30)
*Slide 2 → Slide 3*

> Every AI is only as good as the data it learns from. And there's a real problem here — nobody can share real government VPN traffic, it's too sensitive to release.
>
> So we built our own. We created a virtual lab that copies real-world network conditions — delays, dropped packets, shaky connections, the whole picture. Inside that lab we ran everyday traffic: video calls, voice calls, browsing, email, and simple pings.
>
> The hard part was labelling all of it correctly without any human bias creeping in. We found a clever trick — a small network tag survives even after the data gets encrypted, so we could automatically mark every sample with its true type. We also added real, public capture files to keep things grounded in reality.
>
> The result is ten thousand labelled samples, evenly split across every traffic type — a clean, fair dataset for the AI to learn from.

---

### 3. How the AI Works (2:30 – 4:00)
*Slide 3 → Slide 4*

> So how do we figure out what's flowing through an encrypted tunnel, without decrypting anything? Simple — we never look at the content, only the behaviour. Things like packet size, timing, and rhythm. A video call behaves very differently from an email, even fully encrypted. And we never look at IP addresses or any personal info, so we can't cheat, and nobody's identity can leak.
>
> Under the hood, two AI models work together — one built for speed, one built to be smarter and catch patterns the fast one misses. They vote together on every decision.
>
> And here's the part that matters most for a security tool: Janus never bluffs. Every decision comes with a plain explanation you can actually see. And if it comes across something it's never seen before — a strange custom tool, or traffic that's been deliberately disguised — it doesn't guess. It just says "I'm not sure" and flags it for a human to check.

---

### 4. DEMO 1 — Compliance Check + Auto-Fix (4:00 – 5:30)
*Switch to browser → click Scenario 4*

> Let's see it live. This is the real Janus dashboard, with twelve test tunnels ready to go, from rock-solid to badly outdated. Let's open this old-style one.
>
> *[click]* Straight away — score 25 out of 100, grade F, critical risk. Janus found four real weaknesses here, including two well-known attacks, plus a weak integrity check and a tunnel that never refreshes its keys.
>
> *[scroll to remediation block]* But we don't just point out problems, we fix them. Here's a ready-to-use configuration file with the secure settings already filled in. An engineer copies this, pastes it onto their server, and the tunnel is instantly upgraded. One more click gives a plain-English explanation of why each setting matters, straight from the official standards.

---

### 5. DEMO 2 — AI Traffic Classification (5:30 – 7:00)
*Click Analysis tab → click a flow*

> Now here's the AI in action. This chart shows what kind of traffic is moving through the tunnel — calls, video, browsing, email — all figured out without decrypting a single packet.
>
> *[click a flow]* Let's click on one flow. And here's the part we're proudest of — the AI shows its work. These bars explain exactly why it decided this was a voice call: steady timing, small consistent packets, a classic voice fingerprint.
>
> And if someone tries to disguise their traffic by smoothing it out artificially, Janus notices, flags it as suspicious, and refuses to guess blindly. We can export all of this with one click for a proper audit trail.

---

### 6. DEMO 3 — Compare Tunnels + Reports (7:00 – 8:00)
*Click Compare → click Report*

> Sometimes you need to check many tunnels at once. Here's a strong, modern tunnel side by side with that weak one from earlier — you can instantly see where the gap is.
>
> And finally, one click generates two reports — a short summary for management, and a full technical report for engineers with everything they need to fix it.

---

### 7. Why It Matters (8:00 – 9:00)
*Back to Slide 5 & 6*

> So why does this matter? For defense and government teams, Janus means five things. No more waiting on scarce security experts — this audit takes ten seconds. Zero disruption — no keys needed, nothing installed, fully passive. Ready for the next generation of code-breaking computers. Fully tested, with dozens of automated checks confirming it every time. And built entirely on free, open technology — no expensive foreign software required.

---

### 8. Close (9:00 – 9:20)

> To sum up: Janus never bluffs, never breaks encryption, and never leaves you guessing. It tells you the truth about your tunnel, and helps you fix it instantly.
>
> Thank you — happy to take your questions.

---

## Quick Q&A Backup (plain-language versions)

**"How do you know your AI isn't just tracking IP addresses?"**
We strip out all IP addresses and port numbers before the AI ever sees the data. It only looks at timing and size patterns — nothing that identifies who's talking to who.

**"Can you actually decrypt the traffic?"**
No, and we never claim to — that's not possible, and we wouldn't want it to be. The security check happens during the handshake, before anything is encrypted. After that, we only guess the traffic type from behaviour, never content.

**"What if someone tries to trick your AI?"**
If someone smooths out their traffic to hide its pattern, Janus notices that smoothing and flags it — it doesn't get fooled into guessing anyway.

**"Why two AI models instead of one?"**
One's built for speed, the other catches subtler patterns. Together they're more accurate than either alone.

---

*Delivery note: this script sits at ~90 wpm average — comfortably slower than normal talking speed, on purpose. That gap is your buffer for pauses, eye contact, and demo lag. Read it out loud once with a timer before assuming it's too short.*