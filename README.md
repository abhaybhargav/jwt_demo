## Demo App for JWT Implementation

### Requirements
1. Python 2.7.X
2. dependencies from requirements.txt

### To install
1. Please run pip install -r requirements.txt. You dont need to create another DB. Its already in the repo.
2. The application runs on Flask default port 5000, with debug enabled. 

### How to run
1. You will need to authenticate first with the `/login` REST URI. Valid usernames and passwords include `admin:admin123` and `guest:guest123` Successful authentication gives you a valid JWT that lasts for the current time + 1 minute.
2. To validate a genuine JWT, you need to authenticate with the JWT issued from the `/login` URI to the `/auth` URI with a GET request. You will need to use the HTTP Header `Authorization` with the Token value. 
3. You can pass forged tokens to the app using the `/insecure_auth` URI. This does NOT verify the authenticity of the token, hence is an authentication bypass

