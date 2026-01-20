from fastapi import FastAPI, BackgroundTasks, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import uuid
import os
import requests
import hashlib
import time
from pypdf import PdfWriter, PdfReader

app = FastAPI(title="Minimal PDF Processor (Upload + Merge)")

OUTPUT_DIR = "outputs"
TMP_DIR = "tmp"
UPLOAD_DIR = "uploads"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_INPUT_FILES = 5

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60

# In-memory job store
jobs: Dict[str, Dict[str, Any]] = {}

# In-memory uploaded file store: file_id -> file_path
uploaded_files: Dict[str, Dict[str, Any]] = {}

# Cache store: cache_key -> output_path
cache: Dict[str, str] = {}


# -------------------- Models --------------------

class JobRequest(BaseModel):
    job_type: str

    # Either give URLs OR file_ids (we support both)
    input_files: Optional[List[HttpUrl]] = None
    input_file_ids: Optional[List[str]] = None


class JobStatus(BaseModel):
    job_id: str
    state: str
    progress: int
    result_url: Optional[str] = None
    error: Optional[str] = None
    created_at: float
    updated_at: float
    cached: bool


class UploadResponse(BaseModel):
    file_id: str
    filename: str
    size_bytes: int


# -------------------- Helpers --------------------

def now_ts() -> float:
    return time.time()


def make_cache_key(job_type: str, inputs: List[str]) -> str:
    # Inputs can be URLs or file_ids. We cache based on ordered list.
    raw = job_type.lower().strip() + "|" + "|".join(inputs)
    return hashlib.sha256(raw.encode()).hexdigest()


def cleanup_files(paths: List[str]):
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except:
            pass


def download_pdf(url: str, save_path: str):
    try:
        r = requests.get(url, stream=True, timeout=(
            CONNECT_TIMEOUT, READ_TIMEOUT))
    except Exception as e:
        raise Exception(f"Download failed: {url} ({str(e)})")

    if r.status_code != 200:
        raise Exception(
            f"Failed to download file: {url} (status={r.status_code})")

    total = 0
    with open(save_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 64):
            if chunk:
                total += len(chunk)
                if total > MAX_FILE_SIZE_BYTES:
                    raise Exception(
                        f"File too large (> {MAX_FILE_SIZE_MB}MB): {url}")
                f.write(chunk)


def resolve_inputs_to_local_paths(urls: List[str], file_ids: List[str], job_id: str) -> List[str]:
    """
    Returns list of local file paths to merge.
    - For URLs: download into tmp/
    - For file_ids: use uploads/ path
    """
    local_paths = []
    tmp_downloads = []

    # Add uploaded files
    for fid in file_ids:
        if fid not in uploaded_files:
            raise Exception(f"Invalid file_id: {fid}")

        path = uploaded_files[fid]["path"]
        if not os.path.exists(path):
            raise Exception(f"Uploaded file missing on disk: {fid}")

        local_paths.append(path)

    # Download URL PDFs into tmp
    for i, url in enumerate(urls):
        local_path = os.path.join(TMP_DIR, f"{job_id}_url_{i}.pdf")
        download_pdf(url, local_path)
        tmp_downloads.append(local_path)
        local_paths.append(local_path)

    return local_paths, tmp_downloads


def process_merge_job(job_id: str, urls: List[str], file_ids: List[str], cache_key: str):
    tmp_files = []
    try:
        jobs[job_id]["state"] = "PROCESSING"
        jobs[job_id]["progress"] = 5
        jobs[job_id]["updated_at"] = now_ts()

        local_paths, tmp_downloads = resolve_inputs_to_local_paths(
            urls, file_ids, job_id)
        tmp_files.extend(tmp_downloads)

        jobs[job_id]["progress"] = 50
        jobs[job_id]["updated_at"] = now_ts()

        # Merge PDFs
        writer = PdfWriter()
        for fpath in local_paths:
            reader = PdfReader(fpath)
            for page in reader.pages:
                writer.add_page(page)

        output_path = os.path.join(OUTPUT_DIR, f"{job_id}_merged.pdf")
        with open(output_path, "wb") as out_file:
            writer.write(out_file)

        jobs[job_id]["progress"] = 100
        jobs[job_id]["state"] = "COMPLETED"
        jobs[job_id]["result_path"] = output_path
        jobs[job_id]["updated_at"] = now_ts()

        cache[cache_key] = output_path

    except Exception as e:
        jobs[job_id]["state"] = "FAILED"
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["updated_at"] = now_ts()

    finally:
        cleanup_files(tmp_files)


# -------------------- Routes --------------------

@app.get("/")
def root():
    return {
        "message": "Minimal PDF Processor Backend is running",
        "try": ["/docs", "/upload", "/jobs", "/jobs/{job_id}", "/download/{job_id}"],
    }


@app.post("/upload", response_model=UploadResponse)
async def upload_pdf(file: UploadFile = File(...)):
    # Basic validation
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400, detail="Only PDF files are allowed")

    file_id = str(uuid.uuid4())
    save_path = os.path.join(UPLOAD_DIR, f"{file_id}.pdf")

    size = 0
    with open(save_path, "wb") as f:
        while True:
            chunk = await file.read(1024 * 64)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE_BYTES:
                f.close()
                if os.path.exists(save_path):
                    os.remove(save_path)
                raise HTTPException(
                    status_code=400, detail=f"File too large (> {MAX_FILE_SIZE_MB}MB)")
            f.write(chunk)

    # ✅ NEW: Validate PDF after upload (IMPORTANT FIX)
    try:
        test_reader = PdfReader(save_path)
        _ = len(test_reader.pages)  # force read pages
    except Exception as e:
        if os.path.exists(save_path):
            os.remove(save_path)
        raise HTTPException(
            status_code=400, detail=f"Invalid/corrupt PDF uploaded: {str(e)}")

    uploaded_files[file_id] = {
        "path": save_path,
        "filename": file.filename,
        "size_bytes": size,
        "uploaded_at": now_ts(),
    }

    return UploadResponse(file_id=file_id, filename=file.filename, size_bytes=size)


@app.post("/jobs", response_model=JobStatus)
def create_job(req: JobRequest, background_tasks: BackgroundTasks):
    job_type = req.job_type.lower().strip()

    if job_type != "merge":
        raise HTTPException(
            status_code=400, detail="Only 'merge' job_type is supported currently")

    urls = [str(u) for u in (req.input_files or [])]
    file_ids = req.input_file_ids or []

    if len(urls) == 0 and len(file_ids) == 0:
        raise HTTPException(
            status_code=400, detail="Provide either input_files (URLs) or input_file_ids")

    total_inputs = len(urls) + len(file_ids)

    if total_inputs < 2:
        raise HTTPException(
            status_code=400, detail="Need at least 2 PDFs to merge")

    if total_inputs > MAX_INPUT_FILES:
        raise HTTPException(
            status_code=400, detail=f"Max {MAX_INPUT_FILES} PDFs allowed per job")

    # Cache key based on the exact inputs
    cache_inputs = urls + file_ids
    cache_key = make_cache_key(job_type, cache_inputs)

    # Return cached output if exists
    if cache_key in cache and os.path.exists(cache[cache_key]):
        job_id = str(uuid.uuid4())
        created = now_ts()

        jobs[job_id] = {
            "state": "COMPLETED",
            "progress": 100,
            "result_path": cache[cache_key],
            "error": None,
            "created_at": created,
            "updated_at": created,
            "cached": True,
        }

        return JobStatus(
            job_id=job_id,
            state="COMPLETED",
            progress=100,
            result_url=f"/download/{job_id}",
            error=None,
            created_at=created,
            updated_at=created,
            cached=True,
        )

    job_id = str(uuid.uuid4())
    created = now_ts()

    jobs[job_id] = {
        "state": "PENDING",
        "progress": 0,
        "result_path": None,
        "error": None,
        "created_at": created,
        "updated_at": created,
        "cached": False,
    }

    background_tasks.add_task(
        process_merge_job, job_id, urls, file_ids, cache_key)

    return JobStatus(
        job_id=job_id,
        state=jobs[job_id]["state"],
        progress=jobs[job_id]["progress"],
        result_url=None,
        error=None,
        created_at=jobs[job_id]["created_at"],
        updated_at=jobs[job_id]["updated_at"],
        cached=False,
    )


@app.get("/jobs/{job_id}", response_model=JobStatus)
def get_job_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]

    result_url = None
    if job["state"] == "COMPLETED":
        result_url = f"/download/{job_id}"

    return JobStatus(
        job_id=job_id,
        state=job["state"],
        progress=job["progress"],
        result_url=result_url,
        error=job["error"],
        created_at=job["created_at"],
        updated_at=job["updated_at"],
        cached=job.get("cached", False),
    )


@app.get("/download/{job_id}")
def download_result(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    if job["state"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Job not completed yet")

    path = job["result_path"]
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Result file missing")

    return FileResponse(path, media_type="application/pdf", filename="merged.pdf")
