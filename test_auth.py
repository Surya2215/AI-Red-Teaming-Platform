import httpx
import asyncio
import json

async def test_auth():
    # Create client with explicit cookie jar
    async with httpx.AsyncClient(cookies=httpx.Cookies()) as client:
        # Step 1: Login with form-encoded data
        print('Step 1: Login with form-encoded data')
        login_response = await client.post(
            'http://ec2-13-233-196-8.ap-south-1.compute.amazonaws.com:8000/login',
            data={'username': 'admin', 'password': 'Password@123'},
            follow_redirects=False
        )
        print(f'  Status: {login_response.status_code}')
        print(f'  Headers: {dict(login_response.headers)}')
        print(f'  Client cookies: {dict(client.cookies)}')
        print(f'  Body: {login_response.text}')
        
        # Step 2: Make chat request (should include session cookie)
        print('\nStep 2: Chat request with session cookie')
        chat_response = await client.post(
            'http://ec2-13-233-196-8.ap-south-1.compute.amazonaws.com:8000/chat',
            json={'message': 'Hello'},
        )
        print(f'  Status: {chat_response.status_code}')
        print(f'  Response: {chat_response.text[:300]}')

asyncio.run(test_auth())
