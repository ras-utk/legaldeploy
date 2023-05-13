from fastapi import FastAPI, Response, Header
from pydantic import BaseModel
from fastapi import FastAPI
from pydantic import BaseModel
from pymongo import MongoClient
from fastapi.exceptions import HTTPException
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from bson.json_util import dumps, loads
from passlib.context import CryptContext
from fastapi.encoders import jsonable_encoder
from bson.objectid import ObjectId
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
import requests
from fastapi import FastAPI
from fastapi.responses import Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.responses import JSONResponse
import json
from fastapi import FastAPI, HTTPException, Header
from pymongo import MongoClient
from bson.json_util import dumps, RELAXED_JSON_OPTIONS, ObjectId
from bson import json_util


app = FastAPI()

security = HTTPBasic()

userName={}

firebase_api_url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyA6NGHMWQj8tvGfagIGCe9x1iYTSX7uAXg"

def exclude_id(obj):
    return obj.pop("_id", None)

# Allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient("mongodb+srv://850066763:850066763@cluster0.rmxyg9a.mongodb.net/?retryWrites=true&w=majority")
db = client["Legal_Service_Clinic"]

contracts_collection = db["client_details_contract"]
users_collection = db["client_essentials"]
employee_collection = db["employee_essentials"]
in_progress_collection = db["in_progress_contracts"]
history_collection = db["history_contracts"]
active_collection = db["active_contracts"]

class User(BaseModel):
    fullName: str
    email: str
    username: str
    password: str
    # location:str
    company:str
    phoneNo: str
    position:str

class UserLogin(BaseModel):
    username: str
    password: str

# encrypting password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/api/signup/user")
async def signup(user_signup: User):
    user_dict = user_signup.dict()
    password=user_signup.password
    user_dict["password"] = get_password_hash(user_dict["password"])

    
    print("Inserting user:", user_dict)
    try:
        result = users_collection.insert_one(user_dict)
        print("Insert result:", result)
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail="Could not create user")
    
    payload = {
           "email": user_signup.email,
            "password": password,
            "displayName": user_signup.fullName,
            "returnSecureToken": True
        }
    response = requests.post(firebase_api_url, json=payload)
    print(response.json())
    return {"message": "User created successfully"}



# @app.post("/api/login/user")
# def login(user_login: UserLogin):
#     email = user_login.username
#     password = user_login.password

#     user = users_collection.find_one({"email": email})
#     if user is None or not verify_password(password, user["password"]):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
#     userName.update({"name":user["fullName"],"email": user["email"]})
    
#     # response = Response(content={"message": "Logged in successfully"})
#     # response.set_cookie(key="email_id", value=user["email"])

#     return userName
#     # return RedirectResponse(url=f"localhost:3000/clientdb?username={email}")

@app.post("/api/login/user")
def login(user_login: HTTPBasicCredentials):

    user = users_collection.find_one({"email": user_login.username})
    if user is None or not verify_password(user_login.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    # userName.update({"name":user["fullName"],"email": user["email"]})
    userName.update({"username": user["username"]})
    # response = Response(content={"message": "Logged in successfully"})
    # response.set_cookie(key="email_id", value=user["email"])

    return userName
    # return RedirectResponse(url=f"localhost:3000/clientdb?username={email}")

@app.get("/api/login/user")
async def get_name():
    return userName

@app.get("/contract_form/client/{username}")
def get_contracts(username:str):
    user = users_collection.find_one({"email": username})

    if user is None:
        return JSONResponse(content={"error": "User not found"}, status_code=404)

    contracts = list(in_progress_collection.find())
    
    return "1"


#THIS IS IN-PROGRESS CONTRACTS
@app.get("/in-progress-contracts")
def get_in_progress_contracts(email: str = Header(...)):
    # Query the database for in-progress contracts matching the email ID
    query = {"username": email}
    contracts = in_progress_collection.find(query, projection={"_id":0, "username":0})

    # Check if any contracts found
    if in_progress_collection.count_documents({}) == 0:
        raise HTTPException(status_code=404, detail="No in-progress contracts found for the provided email ID.")

    # Convert contracts to JSON
    json_contracts = json_util.dumps(contracts, indent=4)
    
    print(json_contracts)

    return json_contracts


#THIS IS HISTORY CONTRACTS
@app.get("/history-contracts")
def get_history_contracts(username: str = Header(...)):
    # Query the database for in-progress contracts matching the email ID
    query = {"username": username}
    contracts = history_collection.find(query, projection={"_id":0, "username":0})
    # Check if any contracts found
    if history_collection.count_documents({}) == 0:
        raise HTTPException(status_code=404, detail="No in-progress contracts found for the provided email ID.")

    # Convert contracts to JSON
    json_contracts = json_util.dumps(contracts, indent=4)
    # for obj in json_contracts:
    #     obj.pop("_id", None)
    
    # beautified_json_contracts = json.dumps(json.loads(json_contracts), indent=4)
    print(json_contracts)

    return json_contracts

@app.get("/active-contracts")
def get_active_contracts(username: str = Header(...)):
    # Query the database for in-progress contracts matching the email ID
    query = {"username": username}
    contracts = active_collection.find(query, projection={"_id":0, "username":0})
    # Check if any contracts found
    if active_collection.count_documents({}) == 0:
        raise HTTPException(status_code=404, detail="No in-progress contracts found for the provided email ID.")

    # Convert contracts to JSON
    json_contracts = json_util.dumps(contracts, indent=4)
    # for obj in json_contracts:
    #     obj.pop("_id", None)
    
    # beautified_json_contracts = json.dumps(json.loads(json_contracts), indent=4)
    print(json_contracts)

    return json_contracts
