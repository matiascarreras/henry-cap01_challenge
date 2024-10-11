from fastapi import FastAPI, Depends, HTTPException, status, Query
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List, Optional
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from datetime import datetime, timedelta

# Esquemas Pydantic para los payloads
class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

# Configuración de FastAPI
app = FastAPI()

# Configuración de Passlib para el cifrado de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Clave secreta para firmar los tokens JWT
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simulación de una base de datos en memoria
fake_db = {}

# Esquemas Pydantic
class User(BaseModel):
    username: str
    password: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Utilidad para cifrar contraseñas
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Utilidad para verificar contraseñas
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

"""
Creates an access token (JWT) with the provided data and an optional expiration time.

:param data: A dictionary containing the data to be encoded in the JWT.
:param expires_delta: An optional timedelta specifying the expiration time of the token. If not provided, the token will expire in 30 minutes.
:return: The encoded JWT token as a string.
"""
# Crear un token JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

"""
The `register` function allows a new user to be registered in the application. It takes a `User` object as input, which contains the username and password for the new user.

If the username already exists in the `fake_db` dictionary, an `HTTPException` with a 400 Bad Request status code is raised, indicating that the user already exists.

Otherwise, the password is hashed using the `hash_password` function from the `Passlib` library, and the user's information is stored in the `fake_db` dictionary. Finally, a success message is returned.

:param user: A `User` object containing the username and password for the new user.
:return: A dictionary with a success message.
"""
# Registrar un nuevo usuario
@app.post("/register")
def register(user: User):
    if user.username in fake_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario ya existe")
    hashed_password = hash_password(user.password)
    fake_db[user.username] = {"username": user.username, "password": hashed_password}
    return {"message": "User registered successfully"}

"""
The `login` function allows a user to authenticate and obtain an access token (JWT) for accessing protected endpoints in the application.

The function takes a `User` object as input, which contains the username and password for the user attempting to log in.

If the username does not exist in the `fake_db` dictionary, or the provided password does not match the hashed password stored for the user, an `HTTPException` with a 401 Unauthorized status code is raised, indicating that the credentials are invalid.

Otherwise, an access token is generated using the `create_access_token` function, which encodes the user's username in the token. The access token is then returned in the response as a dictionary with the key "access_token".

:param user: A `User` object containing the username and password for the user attempting to log in.
:return: A dictionary containing the generated access token.
"""
# Iniciar sesión y generar un token JWT
@app.post("/login")
def login(user: User):
    db_user = fake_db.get(user.username)
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales Inválidas")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token}

"""
Verifies the validity of a JWT token provided in a protected endpoint.

This function decodes the provided JWT token using the `SECRET_KEY` and `ALGORITHM` constants. If the token is valid and not expired, the function returns the username associated with the token. If the token is invalid or expired, an `HTTPException` is raised with the appropriate error message and status code.

:param token: The JWT token to be verified.
:return: The username associated with the valid token.
:raises HTTPException: If the token is invalid or expired.
"""
# Dependencia para verificar el token JWT en endpoints protegidos
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        return username
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

# Ejemplo de un endpoint protegido
@app.post("/protected-endpoint")
def protected_endpoint(token: str = Depends(verify_token)):
    return {"message": f"Hola {token}, has accedido a un endpoint protegido"}

"""
The `bubble_sort` function takes a list of integers `arr` as input and returns a new list with the elements sorted in ascending order using the Bubble Sort algorithm.

Bubble Sort is a simple sorting algorithm that repeatedly steps through the list, compares adjacent elements and swaps them if they are in the wrong order. The algorithm continues iterating through the list until the entire list is sorted.

:param arr: A list of integers to be sorted.
:return: A new list with the elements sorted in ascending order.
"""
# Algoritmo de Bubble Sort
def bubble_sort(arr: List[int]) -> List[int]:
    n = len(arr)
    for i in range(n):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
    return arr

"""
The `filter_even_numbers` function takes a list of integers `arr` as input and returns a new list containing only the even numbers from the input list.

:param arr: A list of integers.
:return: A new list containing only the even numbers from the input list `arr`.
"""
# Filtro de números pares
def filter_even_numbers(arr: List[int]) -> List[int]:
    return [num for num in arr if num % 2 == 0]

"""
The `sum_elements` function takes a list of integers `arr` as input and returns the sum of all the elements in the list.

:param arr: A list of integers.
:return: The sum of all the elements in the input list `arr`.
"""
# Suma de elementos de una lista
def sum_elements(arr: List[int]) -> int:
    return sum(arr)

"""
The `max_value` function takes a list of integers `arr` as input and returns the maximum value in the list.

If the input list is empty, the function raises an `HTTPException` with a status code of 400 (Bad Request) and a detail message of "La lista no debe estar vacía".

:param arr: A list of integers.
:return: The maximum value in the input list `arr`.
"""
# Encontrar el valor máximo en una lista
def max_value(arr: List[int]) -> int:
    if not arr:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La lista no debe estar vacía")
    return max(arr)

"""
The `binary_search` function takes a sorted list of integers `arr` and a target integer `target` as input, and returns a tuple indicating whether the target was found in the list and the index of the target if found.

The function uses a binary search algorithm to efficiently search the sorted list for the target value. If the target is found, the function returns `(True, index)`, where `index` is the index of the target in the list. If the target is not found, the function returns `(False, -1)`.

:param arr: A sorted list of integers to search.
:param target: The integer value to search for in the list.
:return: A tuple `(found, index)` where `found` is a boolean indicating whether the target was found, and `index` is the index of the target in the list if found, or -1 if not found.
"""
# Búsqueda binaria
def binary_search(arr: List[int], target: int) -> (bool, int):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return True, mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return False, -1

# Endpoint de Bubble Sort
@app.post("/bubble-sort")
def bubble_sort_endpoint(payload: Payload, token: str = Depends(verify_token)):
    sorted_numbers = bubble_sort(payload.numbers.copy())
    return {"numbers": sorted_numbers}

# Endpoint de filtro de números pares
@app.post("/filter-even")
def filter_even_endpoint(payload: Payload, token: str = Depends(verify_token)):
    even_numbers = filter_even_numbers(payload.numbers)
    return {"even_numbers": even_numbers}

# Endpoint para la suma de elementos
@app.post("/sum-elements")
def sum_elements_endpoint(payload: Payload, token: str = Depends(verify_token)):
    total_sum = sum_elements(payload.numbers)
    return {"sum": total_sum}

# Endpoint para obtener el valor máximo
@app.post("/max-value")
def max_value_endpoint(payload: Payload, token: str = Depends(verify_token)):
    max_num = max_value(payload.numbers)
    return {"max": max_num}

# Endpoint para la búsqueda binaria
@app.post("/binary-search")
def binary_search_endpoint(payload: BinarySearchPayload, token: str = Depends(verify_token)):
    # Aseguramos que la lista está ordenada
    sorted_numbers = sorted(payload.numbers)
    found, index = binary_search(sorted_numbers, payload.target)
    return {"found": found, "index": index}

"""
Recursively sorts the given list of integers using the Quick Sort algorithm.

:param arr: A list of integers to be sorted.
:return: A new sorted list of integers.
"""
# Algoritmo de Quick Sort
def quick_sort(arr: List[int]) -> List[int]:
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quick_sort(left) + middle + quick_sort(right)

@app.post("/quick-sort")
def quick_sort_endpoint(payload: Payload, token: str = Depends(verify_token)):
    sorted_numbers = quick_sort(payload.numbers.copy())
    return {"numbers": sorted_numbers}

"""
Paginates the numbers in the provided payload, returning a subset of the numbers based on the requested page and page size.

:param payload: The payload containing the list of numbers to be paginated.
:param page: The page number to retrieve, starting from 1.
:param page_size: The number of items to return per page.
:return: A dictionary containing the current page number, page size, total number of items, and the paginated data.
"""
@app.get("/paginate")
def paginate_numbers(payload: Payload, page: int = Query(1, ge=1), page_size: int = Query(10, ge=1)):
    start = (page - 1) * page_size
    end = start + page_size
    paginated_numbers = payload.numbers[start:end]
    return {"page": page, "page_size": page_size, "total": len(payload.numbers), "data": paginated_numbers}