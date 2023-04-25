from fastapi import FastAPI
from auth.router import auth_router

# Fast api
app = FastAPI()

# add the authentication routes
app.include_router(auth_router)

# add any additional routes
@app.get("/")
async def root():
    return {"message": "Hello, world!"}


#if __name__ == "__main__":
#
