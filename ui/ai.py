import openai
from dotenv import load_dotenv
import os

load_dotenv()

client = openai.OpenAI(api_key="not-needed", base_url="http://localhost:11434/v1")


def ask_ollama(prompt, model=os.getenv("MODEL"), temperature=0.7, max_tokens=150):
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a malware analysis assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content


def check_single_action(action_resume):
    prompt = f"Is the following action malicious or benign? Answer with 'malicious' or 'benign'. Then provide a brief explanation of your reasoning.\n\nAction: {action_resume}"
    response = ask_ollama(prompt)
    return response.lower().startswith("malicious"), response


message_history = []


def chat_with_ollama(
    user_input, model=os.getenv("MODEL"), temperature=0.7, max_tokens=150
):
    global message_history
    message_history.append({"role": "user", "content": user_input})
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a malware analysis assistant."},
            *message_history,
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    reply = response.choices[0].message.content
    message_history.append({"role": "assistant", "content": reply})
    return reply
