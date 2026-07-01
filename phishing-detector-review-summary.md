# Phishing URL Detector — Review & Enhancement Summary

**Reviewed by:** David Adewale Adepoju  
**Date:** May 2, 2026  
**Tool:** Phishing URL Detector (custom-built by colleague)

---

## What the Tool Does

This is a locally hosted web application that takes any website link (URL) and tells you whether it is likely a **phishing link** (a fake, dangerous link designed to steal your information) or a **safe link**.

It works in two ways at the same time:

- **Machine Learning** — The tool was trained on thousands of examples of both safe and dangerous links. It learned the patterns that make a link look suspicious, the same way a person learns to spot a fake after seeing enough examples.
- **Rule-based checking** — On top of that, it applies a set of manual rules, like "if the link contains an @ symbol, that is suspicious" or "if the link uses an IP address instead of a real website name, that is a red flag."

Both methods work together to give a final verdict.

---

## Errors Found During Review

### Error 1 — The app was stored in the wrong place on the computer

**What happened:** The application files were placed inside a folder called `/var/www/html/`, which is a special area that belongs to Apache — a completely different web server program running on the same computer. When Apache found the files, it just displayed them as plain text instead of running them properly. This caused the web page to show raw code gibberish instead of the actual working interface.

**Why it matters:** It is like putting your car key inside someone else's locker — the wrong system picked it up and had no idea what to do with it.

**What was done:** The entire project was moved to the correct location in the user's home folder, away from Apache's territory.

---

### Error 2 — Required software components were not installed

**What happened:** When we tried to run the application, it immediately crashed because a piece of software it depends on called `joblib` was not installed on the computer. Think of it like trying to run a program that needs Microsoft Word but Word is not installed — it simply refuses to start.

**Why it matters:** Without these components, the application cannot function at all.

**What was done:** All missing components (`joblib`, `flask`, `pandas`, `scikit-learn`) were installed using the terminal.

---

### Error 3 — The training data file was missing

**What happened:** The application needs a file called `dataset.csv` — a large spreadsheet of thousands of example links labelled as either safe or dangerous — to teach itself what to look for. This file was lost during the process of moving the project to the correct folder and could not be located on the system.

**Why it matters:** Without this file, the tool cannot train its brain. It is like asking someone to learn from a textbook that does not exist.

**What was done:** A new dataset was generated from scratch using a script that created realistic examples of both safe URLs and phishing URLs, covering common patterns seen in real-world phishing attacks.

---

## Improvements & Security Enhancements Made

### 1. Better threat detection (the most important improvement)

The original tool only looked at 10 basic things about a link — things like how long it is or whether it contains a hyphen. Several of these checks were nearly useless in practice. One check counted a character (`|`) that almost never appears in any URL at all, safe or dangerous.

The enhanced version now checks 18 signals, including the most reliable phishing indicators that were completely missing before: whether the link uses a raw number address instead of a real website name (a classic phishing trick), how deep the fake subdomains go, whether the link contains brand names being impersonated (like "paypal" or "amazon" on a suspicious domain), and how random and scrambled the link looks overall.

---

### 2. Fixed a flaw that was incorrectly flagging legitimate websites as dangerous

The original tool had a logic problem where any link containing the words "login" and "secure" together was immediately marked as phishing — no questions asked. This would have incorrectly flagged real, legitimate websites like Google's own login page as dangerous. This kind of mistake is called a **false positive**, and in security tools it is a serious problem because it trains people to ignore warnings, even real ones.

The fix: the machine learning result and the rule-based score now work together in a balanced way, rather than one being able to completely override the other.

---

### 3. The tool now shows how confident it is, not just a yes or no

The original version gave a simple answer: phishing or safe. But the underlying model actually produces a confidence percentage — for example, "93% likely to be phishing." The original code was silently throwing that number away.

The enhanced version now shows this confidence score on screen, along with exactly which rules were triggered and why. This gives the user much more context to make their own informed decision, rather than just trusting a single word verdict.

---

### 4. Security hardening of the web application

Three specific security issues were corrected in the application code:

- **Debug mode was left on.** This is a developer-only setting that should never be active in a working application because it can reveal internal code and system details to anyone who triggers an error. It has been turned off.

- **No input validation.** The application would crash with a technical error if someone submitted a request without a URL, instead of giving a clean, controlled response. Proper input checks were added so the app handles bad requests gracefully.

- **Duplicated code.** The core prediction logic was written out twice in two different places in the code. This means any future bug fix would have to be applied in two places — and it is easy to miss one. The logic was consolidated into a single shared function that both parts of the app now use.

---

### 5. Improved command-line tool

The original command-line version (the version you use from the terminal without a web browser) could only check one link at a time. The enhanced version now supports checking an entire list of URLs from a file all at once, and can output the results in a format suitable for further automated processing.

---

## Summary

The original tool demonstrated strong foundational thinking and a genuinely good architectural approach. The enhancements made focused on three areas: making the detection more accurate and harder to fool, fixing logic that was producing incorrect results on legitimate websites, and hardening the application against basic security and reliability issues. The tool is now more capable, more honest about its confidence level, and safer to run.
