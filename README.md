# Trust Scout

Upgrade the NOVAIN TRUST verification engine from heuristic-only scoring to an evidence-driven risk assessment system. Keep the existing Express/TypeScript/PostgreSQL architecture and do not migrate frameworks. Preserve the existing UI and database functionality.

For website verification, separate the assessment into HTTPS/infrastructure, domain, identity, reputation, content, and anomaly signals. Each signal must have a source, observation, timestamp, confidence, and explanation. Do not treat HTTPS or successful HTTP response as evidence that a website is trustworthy.

Implement risk gates so that unresolved identity or high-severity security indicators can cap the maximum trust score. Make the final score explainable: every score contribution must map to stored evidence.

Do not invent external verification results. If an external data source is unavailable, explicitly mark the signal as unavailable rather than assigning a positive score.

Update the verification response and UI to distinguish: VERIFIED, UNVERIFIED, WARNING, HIGH RISK, and CRITICAL. Include an evidence list showing exactly what was checked and where the evidence came from.

Keep the existing PostgreSQL persistence and verificationId system. Run typecheck and test the endpoint after implementation.

Then test it with several very different sites                                                    ...Yes. For NOVAIN TRUST, I’d build the API as a normal web API first, then add x402 payments + MCP after the verification engine works.



Because you’re working from a smartphone, the simplest route is Replit or another browser-based development environment. You don't need to manage a VPS initially.



1. What you're actually building



Your first API can be:



NOVAIN TRUST API

        │

        ├── POST /v1/verify/website

        ├── POST /v1/verify/company

        └── GET  /v1/health



An AI agent sends:



{

  "target": "https://example.com"

}



Your API processes it and returns something like:



{

  "trust_score": 82,

  "risk_level": "low",

  "confidence": 0.91,

  "checks": {

    "https": "pass",

    "domain": "pass",

    "identity": "pass",

    "reputation": "pass",

    "anomalies": "warning"

  },

  "recommendation": "Proceed with additional payment verification.",

  "checked_at": "2026-08-11T20:00:00Z"

}



That's the product.





---



2. Use this architecture



For your first version:



AI AGENT

                   │

                   ▼

              NOVAIN API

                   │

       ┌───────────┼───────────┐

       ▼           ▼           ▼

   Website      Company      Risk

   Analysis    Analysis    Engine

       │           │           │

       └───────────┼───────────┘

                   ▼

              Trust Score

                   │

                   ▼

                RESULT



Later:



AI Agent

   │

   ▼

MCP Connector

   │

   ▼

NOVAIN API

   │

   ▼

x402 Payment

   │

   ▼

USDC





---



3. The technology



I'd use:



Backend: Python + FastAPI



Database: PostgreSQL



Hosting: Replit initially



Authentication: API keys initially



Payments: x402 later



AI interface: MCP later



Data sources: legitimate APIs/public sources with permission



FastAPI is particularly suitable because it automatically generates OpenAPI documentation, making your API easier for developers and AI tooling to understand.





---



4. Build the first endpoint



Your first endpoint should be:



POST /v1/verify/website



The request:



{

  "url": "https://example.com"

}



The server then performs your verification workflow.



Conceptually:



def verify_website(url):



    domain = extract_domain(url)



    ssl_check = check_https(url)

    domain_check = check_domain(domain)

    reputation = check_reputation(domain)

    identity = check_identity(url)

    anomalies = detect_anomalies(...)



    score = calculate_trust_score(

        ssl_check,

        domain_check,

        reputation,

        identity,

        anomalies

    )



    return result



The important thing is that the scoring engine belongs to NOVAIN.



You're not simply asking ChatGPT:



> "Is this website safe?"







You're collecting evidence and producing a reproducible assessment.





---



5. Your Trust Score



For example, start with five components:



Identity             25%

Domain/Infrastructure 20%

Reputation            20%

Security              20%

Evidence consistency  15%



Then calculate:



0–29     CRITICAL

30–49    HIGH RISK

50–69    MEDIUM

70–84    LOW

85–100   VERY LOW



But don't present this as an objective universal truth. It's NOVAIN's risk model.



Later, you can improve it using historical outcomes and statistical calibration.





---



6. The most important part: evidence



This is where NOVAIN could become much more valuable than a generic AI wrapper.



Every result should have:



SOURCE

WHAT WAS CHECKED

RESULT

TIMESTAMP

CONFIDENCE



For example:



Domain:

Registered: Yes

Observed age: 4 years

Source: Domain intelligence provider

Checked: 11 Aug 2026



Website:

HTTPS: Valid

Certificate: Valid

Checked: 11 Aug 2026



Identity:

Company name matches website: Yes

Confidence: 93%



This allows the AI to explain why NOVAIN reached its conclusion.





---



7. Then make it paid



Once the API works without payments, add x402.



The flow becomes:



AI asks NOVAIN

       ↓

NOVAIN responds:

402 PAYMENT REQUIRED

       ↓

AI agent pays

       ↓

NOVAIN verifies payment

       ↓

NOVAIN performs verification

       ↓

Result returned



You could start with:



Quick verification       $0.01

Standard verification     $0.05

Deep verification         $0.25



Again, these are test pricing ideas. You should measure actual infrastructure/data costs before setting production prices.





---



8. Then connect AI agents



This is where MCP becomes important.



You expose:



novain_verify_website

novain_verify_company

novain_assess_risk



Then an AI agent can effectively reason:



> "I need to check this website."







→ call NOVAIN



> "NOVAIN returned medium risk."







→ explain the evidence to the user.



You aren't trying to replace Claude or ChatGPT.



You're giving them a specialized capability.





---



9. Don't make this mistake



Don't start by building:



❌ website

❌ mobile app

❌ giant dashboard

❌ cryptocurrency token

❌ complicated PayBox integration

❌ 50 endpoints



Start with:



ONE endpoint.



POST /v1/verify/website



Make that endpoint actually good.



Then:



website verification

       ↓

company verification

       ↓

seller verification

       ↓

payment destination verification

       ↓

document verification

       ↓

general risk intelligence





---



10. What I'd build first for you



Since you want this to be global rather than Nigeria-specific, I'd structure the project like this:



NOVAIN TRUST

│

├── API

│   ├── /verify/website

│   ├── /verify/company

│   ├── /verify/seller

│   └── /risk/assess

│

├── TRUST ENGINE

│   ├── Identity

│   ├── Reputation

│   ├── Infrastructure

│   ├── Security

│   ├── Evidence

│   └── Risk scoring

│

├── PAYMENTS

│   └── x402

│

├── AI

│   └── MCP

│

└── DATABASE

    ├── Checks

    ├── Sources

    ├── Results

    └── Usage



The first milestone



Don't worry about making money yet.



Get this working:



> Send a URL → NOVAIN investigates it → NOVAIN returns a structured trust/risk report.







Once that's working reliably, we can add x402 so an AI agent can pay NOVAIN automatically, and then expose it to Claude/ChatGPT-compatible agent workflows.



If you want to actually build it now, I can give you the complete Replit project structure and the first working FastAPI code, step-by-step, designed so you can do the whole setup from your Android phone.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/2599dcf6-17c5-4281-92a6-3fdfdc7d6da5).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
