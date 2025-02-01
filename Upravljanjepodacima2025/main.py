from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from typing import List, Optional
from passlib.context import CryptContext
import redis
import json


# Konfiguracija baze podataka
DATABASE_URL = "mysql+pymysql://root:db2025@localhost/librarydb"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Konfiguracija Redis-a
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Konfiguracija za hashiranje lozinki
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modeli (SQLAlchemy)
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

# Kreiranje svih tablica u bazi podataka
Base.metadata.create_all(bind=engine)

# Pydantic Šeme
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


# FastAPI aplikacija
app = FastAPI()

# Ovisnost za bazu podataka
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Funkcije za hashiranje lozinke
def hash_lozinka(lozinka: str) -> str:
    return pwd_context.hash(lozinka)

def provjeri_lozinku(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# CRUD rute
@app.post("/registracija", response_model=KorisnikOdgovor)
def registracija(korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    # Provjera je li email već registriran
    postojeći_korisnik = db.query(Korisnik).filter(Korisnik.email == korisnik.email).first()
    if postojeći_korisnik:
        raise HTTPException(status_code=400, detail="Email već registriran.")

    # Hashiranje lozinke i spremanje novog korisnika
    hashirana_lozinka = hash_lozinka(korisnik.lozinka)
    db_korisnik = Korisnik(ime=korisnik.ime, email=korisnik.email, hashed_password=hashirana_lozinka)
    db.add(db_korisnik)
    db.commit()
    db.refresh(db_korisnik)

    return db_korisnik

@app.post("/prijava")
def prijava(korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    db_korisnik = db.query(Korisnik).filter(Korisnik.email == korisnik.email).first()
    if not db_korisnik or not provjeri_lozinku(korisnik.lozinka, db_korisnik.hashed_password):
        raise HTTPException(status_code=400, detail="Neispravni podaci.")
    return {"poruka": "Prijava uspješna"}


## Korisnici
@app.post("/korisnici", response_model=KorisnikOdgovor, tags=["Korisnici"])
def kreiraj_korisnika(novi_korisnik: KorisnikKreiraj, db: Session = Depends(get_db)):
    # Provjera je li korisnik već registriran
    postojeći_korisnik = db.query(Korisnik).filter(Korisnik.email == novi_korisnik.email).first()
    if postojeći_korisnik:
        raise HTTPException(status_code=400, detail="Email već registriran")

    # Kreiranje novog korisnika
    hashirana_lozinka = hash_lozinka(novi_korisnik.lozinka)
    db_korisnik = Korisnik(ime=novi_korisnik.ime, email=novi_korisnik.email, hashed_password=hashirana_lozinka)
    db.add(db_korisnik)
    db.commit()
    db.refresh(db_korisnik)

    # Brisanje cachea za korisnike u Redis-u
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


## Knjige
@app.post("/knjige/", response_model=KnjigaOdgovor, tags=["Knjige"])
def kreiraj_knjigu(knjiga: KnjigaKreiraj, db: Session = Depends(get_db)):
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
def popis_knjiga(db: Session = Depends(get_db)):
    cache_knjiga = redis_client.get("knjige")
    if cache_knjiga:
        return json.loads(cache_knjiga)

    knjige = db.query(Knjiga).all()
    knjige_lista = [{"id": knjiga.id, "naslov": knjiga.naslov, "opis": knjiga.opis} for knjiga in knjige]
    redis_client.set("knjige", json.dumps(knjige_lista))

    return knjige
