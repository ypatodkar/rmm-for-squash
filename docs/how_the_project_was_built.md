# How the Project Was Built

## The AI Tools Used
* **Claude Code (with Claude Opus 5):** This was my main coding assistant. I used it for almost all the code (42 out of 43 updates), including the Windows agent, the main server, the AI driver, tests, and guides.
* **Codex:** I used this alongside Claude. I'd ask both of them the same design questions (like how the system should securely talk to devices) and compare their answers. Codex also double-checked the security and requirements at the end, helping me catch and fix several bugs.
* **OpenAI GPT-4.1:** This is the brain behind the AI that actually diagnoses and fixes computer problems in the finished app. It's built directly into the product, not just a tool I used to write the code.

## Step-by-Step Build Process
1. **Set up the servers:** I created test Windows computers and a main Linux server in the cloud (AWS).
2. **Connect the computers:** I wrote a small program for the Windows computers so they could securely connect back to the main server.
3. **Figure out the rules:** Claude, Codex, and I worked out exactly how the server and computers should talk to each other securely.
4. **Build a control panel:** I made a web dashboard to see all the connected computers and what they were doing.
5. **Create the AI Doctor:** I built an AI that can read a problem description (like "the computer is slow"), check the computer's health, and figure out what's wrong.
6. **Create the AI Mechanic:** I built a second AI that takes the diagnosis and suggests a specific, pre-approved script to fix it. A human always has to click "approve" before it runs.

## Who Did What (Me vs. the AI)
I didn't just let the AI build everything blindly. We split the work:
* **My role:** I made the big decisions. I chose the overall design, set strict security rules, reviewed the AI's code, and tested it on real computers.
* **The AI's role:** The AI assistants wrote the actual code, the tests, and the documentation drafts. I pushed back and made them fix things when tests failed or security looked weak.

**Key design choices I made:**
* Computers reach out to the server (not the other way around) so they don't need vulnerable open network ports.
* Computers use a highly secure "private key" to prove who they are, preventing spoofing.
* The AI can't just invent code; it can only pick from a strict menu of safe, pre-approved actions.
* A human must approve the exact fix before it runs.
* The system double-checks if a fix actually worked by re-testing the computer, rather than just trusting the AI's guess.

## Testing and Checking
* **Automated Tests:** I ran hundreds of automated tests on the server and the AI to make sure they followed the rules, even without a live internet connection.
* **Real-World Tests:** I deliberately broke test computers in the cloud to see if the AI could figure it out. Once I fixed an early bug where the AI wasn't getting enough data, it correctly diagnosed and fixed 12 out of 12 problems during development.

## Time Spent
The whole project took me about 17 to 20 hours of hands-on work, spread across 43 saved updates to the code.