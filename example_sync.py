"""
Example of using maxhttp in synchronous mode.

sync mode auto enabled.
"""

from maxhttp import Client, RetryPolicy


# Now you can use Client synchronously (no await needed)
if __name__ == "__main__":
    retry = RetryPolicy(max_attempts=2)
    
    # Sync context manager usage
    # Note: use HTTP because this environment blocks outbound TLS handshakes.
    with Client(base_url="https://httpbin.org", retry=retry) as client:
        # All methods are now synchronous
        resp = client.get("/get")
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.json()}")
        
        # POST request
        resp2 = client.post("/post", json={"test": "data"})
        print(f"POST Status: {resp2.status_code}")
        print(f"POST Response: {resp2.json()}")
        
        # Streaming response
        resp3 = client.get("/stream/5", stream=True)
        print("Streaming chunks:")
        for chunk in resp3.iter_bytes():
            print(f"  Received: {chunk[:50]}...")  # Print first 50 bytes
        
        # Text iteration
        resp4 = client.get("/stream/3", stream=True)
        print("Text chunks:")
        for text_chunk in resp4.iter_text():
            print(f"  Text: {text_chunk}")

