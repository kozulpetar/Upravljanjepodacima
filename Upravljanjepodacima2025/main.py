from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from typing import List, Optional
from passlib.context import CryptContext
import redis
import json
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import status
from jose import JWTError, jwt
from datetime import datetime, timedelta

DATABASE_URL = "mysql+pymysql://root:db2025@localhost/librarydb"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "tajni_kljuc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="prijava")

def kreiraj_jwt_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def dekodiraj_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Dekodirani payload:", payload) 
        return payload
    except JWTError as e:
        print("JWTError:", str(e)) 
        return None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_trenutni_korisnik(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = dekodiraj_jwt_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Neispravan token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    korisnik_id = payload.get("sub")
    if not korisnik_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ne sadrži ID korisnika",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        korisnik_id = int(korisnik_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Neispravan ID korisnika u tokenu",
            headers={"WWW-Authenticate": "Bearer"},
        )

    korisnik = db.query(Korisnik).filter(Korisnik.id == korisnik_id).first()
    if not korisnik:
        raise HTTPException(status_code=404, detail="Korisnik nije pronađen")

    return korisnik

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Knjiga(Base):
    __tablename__ = "knjige"
    id = Column(Integer, primary_key=True, index=True)
    naslov = Column(String(100), nullable=False)
    opis = Column(String(255))
    autor_id = Column(Integer, ForeignKey("autori.id"), nullable=True)

    autor = relationship("Autor", back_populates="knjige")
    
class Autor(Base):
    __tablename__ = "autori"
    id = Column(Integer, primary_key=True, index=True)
    ime = Column(String(100), nullable=False)

    knjige = relationship("Knjiga", back_populates="autor", cascade="all, delete")

class Korisnik(Base):
    __tablename__ = "korisnici"
    id = Column(Integer, primary_key=True, index=True)
    ime = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

class Recenzija(Base):
    __tablename__ = "recenzije"
    id = Column(Integer, primary_key=True, index=True)
    ocjena = Column(String(50), nullable=False)
    knjiga_id = Column(Integer, ForeignKey("knjige.id"))

    knjiga = relationship("Knjiga")

class Rezervacija(Base):
    __tablename__ = "rezervacije"
    id = Column(Integer, primary_key=True, index=True)
    knjiga_id = Column(Integer, ForeignKey("knjige.id"))
    korisnik_id = Column(Integer, ForeignKey("korisnici.id"))

    knjiga = relationship("Knjiga")
    korisnik = relationship("Korisnik")

Base.metadata.create_all(bind=engine)

class KnjigaKreiraj(BaseModel):
    naslov: str
    opis: Optional[str] = None
    autor_id: Optional[int] = None


class KnjigaOdgovor(KnjigaKreiraj):
    id: int

    class Config:
        orm_mode = True

class AutorKreiraj(BaseModel):
    ime: str

class AutorOdgovor(AutorKreiraj):
    id: int

    class Config:
        orm_mode = True


class KorisnikKreiraj(BaseModel):
    ime: str
    email: str
    lozinka: str

class KorisnikOdgovor(BaseModel):
    id: int
    ime: str
    email: str

    class Config:
        orm_mode = True

class RecenzijaKreiraj(BaseModel):
    ocjena: str
    knjiga_id: int

class RecenzijaOdgovor(RecenzijaKreiraj):
    id: int

    class Config:
        orm_mode = True

class RezervacijaKreiraj(BaseModel):
    knjiga_id: int
    korisnik_id: int

class RezervacijaOdgovor(RezervacijaKreiraj):
    id: int
    korisnik_id: int
    knjiga_id: int

    class Config:
        orm_mode = True

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_lozinka(lozinka: str) -> str:
    return pwd_context.hash(lozinka)

def provjeri_lozinku(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/registracija", response_model=KorisnikOdgovor)
def registracija(korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    postojeći_korisnik = db.query(Korisnik).filter(Korisnik.email == korisnik.email).first()
    if postojeći_korisnik:
        raise HTTPException(status_code=400, detail="Email već registriran.")

    hashirana_lozinka = hash_lozinka(korisnik.lozinka)
    db_korisnik = Korisnik(ime=korisnik.ime, email=korisnik.email, hashed_password=hashirana_lozinka)
    db.add(db_korisnik)
    db.commit()
    db.refresh(db_korisnik)

    return db_korisnik

@app.post("/prijava", tags=["Autentifikacija"])
def prijava(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    korisnik = db.query(Korisnik).filter(Korisnik.email == form_data.username).first()
    if not korisnik or not provjeri_lozinku(form_data.password, korisnik.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Neispravni podaci za prijavu")

    access_token = kreiraj_jwt_token({"sub": str(korisnik.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/korisnici", response_model=KorisnikOdgovor, tags=["Korisnici"])
def kreiraj_korisnika(novi_korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    postojeći_korisnik = db.query(Korisnik).filter(Korisnik.email == novi_korisnik.email).first()
    if postojeći_korisnik:
        raise HTTPException(status_code=400, detail="Email već registriran")

    hashirana_lozinka = hash_lozinka(novi_korisnik.lozinka)
    db_korisnik = Korisnik(ime=novi_korisnik.ime, email=novi_korisnik.email, hashed_password=hashirana_lozinka)
    db.add(db_korisnik)
    db.commit()
    db.refresh(db_korisnik)

    try:
        redis_client.delete("korisnici")
    except Exception as e:
        print(f"Greška pri čišćenju Redis cache-a: {e}")

    return db_korisnik


@app.get("/korisnici/", response_model=List[KorisnikOdgovor], tags=["Korisnici"])
def popis_korisnika(db: Session = Depends(get_db)):
    korisnici = redis_client.get("korisnici")
    if korisnici:
        return json.loads(korisnici)

    korisnici = db.query(Korisnik).all()
    korisnici_lista = [{"id": korisnik.id, "ime": korisnik.ime, "email": korisnik.email} for korisnik in korisnici]
    redis_client.set("korisnici", json.dumps(korisnici_lista))

    return korisnici


@app.put("/korisnici/{korisnik_id}", response_model=KorisnikOdgovor, tags=["Korisnici"])
def ažuriraj_korisnika(korisnik_id: int, ažurirani_korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    db_korisnik = db.query(Korisnik).filter(Korisnik.id == korisnik_id).first()
    if not db_korisnik:
        raise HTTPException(status_code=404, detail="Korisnik nije pronađen")

    db_korisnik.ime = ažurirani_korisnik.ime
    db_korisnik.email = ažurirani_korisnik.email
    db_korisnik.hashed_password = hash_lozinka(ažurirani_korisnik.lozinka)
    db.commit()
    db.refresh(db_korisnik)

    try:
        redis_client.delete("korisnici")
    except Exception as e:
        print(f"Greška pri čišćenju Redis cache-a: {e}")

    return db_korisnik

@app.delete("/korisnici/{korisnik_id}", tags=["Korisnici"])
def izbriši_korisnika(korisnik_id: int, db: Session = Depends(get_db)):
    db_korisnik = db.query(Korisnik).filter(Korisnik.id == korisnik_id).first()
    if not db_korisnik:
        raise HTTPException(status_code=404, detail="Korisnik nije pronađen")

    db.query(Rezervacija).filter(Rezervacija.korisnik_id == korisnik_id).delete()
    db.delete(db_korisnik)
    db.commit()

    redis_client.delete(f"korisnik:{korisnik_id}")
    redis_client.delete("korisnici")

    return

@app.post("/knjige/", response_model=KnjigaOdgovor, tags=["Knjige"])
def kreiraj_knjigu(knjiga: KnjigaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    if knjiga.autor_id:
        autor = db.query(Autor).filter(Autor.id == knjiga.autor_id).first()
        if not autor:
            raise HTTPException(status_code=400, detail="Autor ne postoji")

    db_knjiga = Knjiga(naslov=knjiga.naslov, opis=knjiga.opis, autor_id=knjiga.autor_id)
    db.add(db_knjiga)
    db.commit()
    db.refresh(db_knjiga)

    redis_client.delete("knjige")

    return db_knjiga

@app.get("/knjige/", response_model=List[KnjigaOdgovor], tags=["Knjige"])
def dohvati_knjige(db: Session = Depends(get_db)):
    knjige = db.query(Knjiga).all()
    return knjige

@app.get("/knjige/{knjiga_id}", response_model=KnjigaOdgovor, tags=["Knjige"])
def dohvati_knjigu(knjiga_id: int, db: Session = Depends(get_db)):
    knjiga = db.query(Knjiga).filter(Knjiga.id == knjiga_id).first()
    if not knjiga:
        raise HTTPException(status_code=404, detail="Knjiga nije pronađena")
    return knjiga

@app.put("/knjige/{knjiga_id}", response_model=KnjigaOdgovor, tags=["Knjige"])
def ažuriraj_knjigu(knjiga_id: int, knjiga: KnjigaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_knjiga = db.query(Knjiga).filter(Knjiga.id == knjiga_id).first()
    if not db_knjiga:
        raise HTTPException(status_code=404, detail="Knjiga nije pronađena")

    db_knjiga.naslov = knjiga.naslov
    db_knjiga.opis = knjiga.opis
    db_knjiga.autor_id = knjiga.autor_id
    db.commit()
    db.refresh(db_knjiga)

    redis_client.delete("knjige")

    return db_knjiga

@app.delete("/knjige/{knjiga_id}", tags=["Knjige"])
def izbriši_knjigu(knjiga_id: int, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_knjiga = db.query(Knjiga).filter(Knjiga.id == knjiga_id).first()
    if not db_knjiga:
        raise HTTPException(status_code=404, detail="Knjiga nije pronađena")

    db.query(Recenzija).filter(Recenzija.knjiga_id == knjiga_id).delete()

    db.delete(db_knjiga)
    db.commit()

    redis_client.delete("knjige")

    return {"message": "Knjiga uspješno obrisana"}

@app.post("/autori/", response_model=AutorOdgovor, tags=["Autori"])
def kreiraj_autora(autor: AutorKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_autor = Autor(ime=autor.ime)
    db.add(db_autor)
    db.commit()
    db.refresh(db_autor)

    redis_client.delete("autori")

    return db_autor

@app.get("/autori/", response_model=List[AutorOdgovor], tags=["Autori"])
def dohvati_autore(db: Session = Depends(get_db)):
    autori = db.query(Autor).all()
    return autori

@app.get("/autori/{autor_id}", response_model=AutorOdgovor, tags=["Autori"])
def dohvati_autora(autor_id: int, db: Session = Depends(get_db)):
    autor = db.query(Autor).filter(Autor.id == autor_id).first()
    if not autor:
        raise HTTPException(status_code=404, detail="Autor nije pronađen")
    return autor

@app.put("/autori/{autor_id}", response_model=AutorOdgovor, tags=["Autori"])
def ažuriraj_autora(autor_id: int, autor: AutorKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_autor = db.query(Autor).filter(Autor.id == autor_id).first()
    if not db_autor:
        raise HTTPException(status_code=404, detail="Autor nije pronađen")

    db_autor.ime = autor.ime
    db.commit()
    db.refresh(db_autor)

    redis_client.delete("autori")

    return db_autor

@app.delete("/autori/{autor_id}", tags=["Autori"])
def izbriši_autora(autor_id: int, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_autor = db.query(Autor).filter(Autor.id == autor_id).first()
    if not db_autor:
        raise HTTPException(status_code=404, detail="Autor nije pronađen")

    db.delete(db_autor)
    db.commit()

    redis_client.delete("autori")

    return

@app.post("/recenzije/", response_model=RecenzijaOdgovor, tags=["Recenzije"])
def kreiraj_recenziju(recenzija: RecenzijaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_recenzija = Recenzija(ocjena=recenzija.ocjena, knjiga_id=recenzija.knjiga_id)
    db.add(db_recenzija)
    db.commit()
    db.refresh(db_recenzija)

    redis_client.delete("recenzije")

    return db_recenzija

@app.get("/recenzije/", response_model=List[RecenzijaOdgovor], tags=["Recenzije"])
def dohvati_recenzije(db: Session = Depends(get_db)):
    recenzije = db.query(Recenzija).all()
    return recenzije

@app.get("/recenzije/{recenzija_id}", response_model=RecenzijaOdgovor, tags=["Recenzije"])
def dohvati_recenziju(recenzija_id: int, db: Session = Depends(get_db)):
    recenzija = db.query(Recenzija).filter(Recenzija.id == recenzija_id).first()
    if not recenzija:
        raise HTTPException(status_code=404, detail="Recenzija nije pronađena")
    return recenzija

@app.put("/recenzije/{recenzija_id}", response_model=RecenzijaOdgovor, tags=["Recenzije"])
def ažuriraj_recenziju(recenzija_id: int, recenzija: RecenzijaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_recenzija = db.query(Recenzija).filter(Recenzija.id == recenzija_id).first()
    if not db_recenzija:
        raise HTTPException(status_code=404, detail="Recenzija nije pronađena")

    db_recenzija.ocjena = recenzija.ocjena
    db_recenzija.knjiga_id = recenzija.knjiga_id
    db.commit()
    db.refresh(db_recenzija)

    redis_client.delete("recenzije")

    return db_recenzija

@app.delete("/recenzije/{recenzija_id}", tags=["Recenzije"])
def izbriši_recenziju(recenzija_id: int, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_recenzija = db.query(Recenzija).filter(Recenzija.id == recenzija_id).first()
    if not db_recenzija:
        raise HTTPException(status_code=404, detail="Recenzija nije pronađena")

    db.delete(db_recenzija)
    db.commit()

    redis_client.delete("recenzije")

    return

@app.get("/rezervacije/", response_model=List[RezervacijaOdgovor], tags=["Rezervacije"])
def dohvati_rezervacije(db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    rezervacije = db.query(Rezervacija).all()
    return rezervacije


@app.post("/rezervacije/", response_model=RezervacijaOdgovor, tags=["Rezervacije"])
def kreiraj_rezervaciju(rezervacija: RezervacijaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
   
    db_knjiga = db.query(Knjiga).filter(Knjiga.id == rezervacija.knjiga_id).first()
    if not db_knjiga:
        raise HTTPException(status_code=404, detail="Knjiga nije pronađena")

    db_korisnik = db.query(Korisnik).filter(Korisnik.id == rezervacija.korisnik_id).first()
    if not db_korisnik:
        raise HTTPException(status_code=404, detail="Korisnik nije pronađen")

    db_rezervacija = Rezervacija(knjiga_id=rezervacija.knjiga_id, korisnik_id=rezervacija.korisnik_id)
    db.add(db_rezervacija)
    db.commit()
    db.refresh(db_rezervacija)

    redis_client.delete("rezervacije")

    return db_rezervacija

@app.put("/rezervacije/{rezervacija_id}", response_model=RezervacijaOdgovor, tags=["Rezervacije"])
def ažuriraj_rezervaciju(rezervacija_id: int, rezervacija: RezervacijaKreiraj, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_rezervacija = db.query(Rezervacija).filter(Rezervacija.id == rezervacija_id).first()
    if not db_rezervacija:
        raise HTTPException(status_code=404, detail="Rezervacija nije pronađena")

    db_knjiga = db.query(Knjiga).filter(Knjiga.id == rezervacija.knjiga_id).first()
    if not db_knjiga:
        raise HTTPException(status_code=404, detail="Knjiga nije pronađena")

    db_korisnik = db.query(Korisnik).filter(Korisnik.id == rezervacija.korisnik_id).first()
    if not db_korisnik:
        raise HTTPException(status_code=404, detail="Korisnik nije pronađen")

    db_rezervacija.knjiga_id = rezervacija.knjiga_id
    db_rezervacija.korisnik_id = rezervacija.korisnik_id
    db.commit()
    db.refresh(db_rezervacija)

    redis_client.delete("rezervacije")

    return db_rezervacija

@app.delete("/rezervacije/{rezervacija_id}", tags=["Rezervacije"])
def izbriši_rezervaciju(rezervacija_id: int, db: Session = Depends(get_db), trenutni_korisnik: Korisnik = Depends(get_trenutni_korisnik)):
    db_rezervacija = db.query(Rezervacija).filter(Rezervacija.id == rezervacija_id).first()
    if not db_rezervacija:
        raise HTTPException(status_code=404, detail="Rezervacija nije pronađena")

    db.delete(db_rezervacija)
    db.commit()

    redis_client.delete("rezervacije")

    return

