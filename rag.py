"""
PDF RAG server using FastAPI + MCP.

Install:
    pip install "mcp[cli]" fastapi uvicorn pypdf \
        sentence-transformers numpy python-multipart

Run HTTP + MCP:
    python pdf_rag_mcp_server.py

Run MCP over stdio:
    python pdf_rag_mcp_server.py --stdio
"""

import hashlib
import io
import re
import sys
from contextlib import asynccontextmanager
from threading import RLock

import numpy as np
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer
from starlette.concurrency import run_in_threadpool

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_PAGES = 300
MAX_RESULTS = 20
CHUNK_SIZE = 1_000
CHUNK_OVERLAP = 150

EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")


# ---------------------------------------------------------------------------
# RAG store
# ---------------------------------------------------------------------------

class RagStore:
    def __init__(self):
        self._lock = RLock()
        self.chunks: list[dict] = []
        self.embeddings: np.ndarray | None = None
        self.document_ids: set[str] = set()

    @staticmethod
    def _normalize_text(text: str) -> str:
        text = text.replace("\x00", " ")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def _chunk_text(text: str) -> list[str]:
        chunks = []
        start = 0

        while start < len(text):
            end = min(start + CHUNK_SIZE, len(text))
            piece = text[start:end]

            # Try not to cut a sentence in half.
            if end < len(text):
                sentence_end = max(
                    piece.rfind(". "),
                    piece.rfind("? "),
                    piece.rfind("! "),
                    piece.rfind("\n"),
                )
                if sentence_end > CHUNK_SIZE // 2:
                    piece = piece[: sentence_end + 1]
                    end = start + len(piece)

            piece = piece.strip()
            if piece:
                chunks.append(piece)

            next_start = end - CHUNK_OVERLAP
            start = max(next_start, start + 1)

        return chunks

    def add_pdf(self, filename: str, data: bytes) -> dict:
        document_id = hashlib.sha256(data).hexdigest()

        with self._lock:
            if document_id in self.document_ids:
                return {
                    "document_id": document_id,
                    "chunks_indexed": 0,
                    "duplicate": True,
                    "pages_without_text": 0,
                }

        reader = PdfReader(io.BytesIO(data))

        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported")

        if len(reader.pages) > MAX_PAGES:
            raise ValueError(f"PDF exceeds the {MAX_PAGES}-page limit")

        new_chunks = []
        pages_without_text = 0

        for page_number, page in enumerate(reader.pages, start=1):
            text = self._normalize_text(page.extract_text() or "")

            if not text:
                pages_without_text += 1
                continue

            for chunk_index, text_chunk in enumerate(self._chunk_text(text)):
                new_chunks.append(
                    {
                        "document_id": document_id,
                        "source": filename,
                        "page": page_number,
                        "chunk_index": chunk_index,
                        "text": text_chunk,
                    }
                )

        if not new_chunks:
            return {
                "document_id": document_id,
                "chunks_indexed": 0,
                "duplicate": False,
                "pages_without_text": pages_without_text,
            }

        vectors = EMBED_MODEL.encode(
            [chunk["text"] for chunk in new_chunks],
            normalize_embeddings=True,
            convert_to_numpy=True,
        ).astype(np.float32)

        with self._lock:
            self.chunks = [*self.chunks, *new_chunks]
            self.embeddings = (
                vectors
                if self.embeddings is None
                else np.vstack((self.embeddings, vectors))
            )
            self.document_ids.add(document_id)

        return {
            "document_id": document_id,
            "chunks_indexed": len(new_chunks),
            "duplicate": False,
            "pages_without_text": pages_without_text,
        }

    def search(
        self,
        query: str,
        k: int = 4,
        document_id: str | None = None,
    ) -> list[dict]:
        query = query.strip()
        if not query:
            return []

        k = max(1, min(k, MAX_RESULTS))

        with self._lock:
            if self.embeddings is None or not self.chunks:
                return []

            chunks = list(self.chunks)
            embeddings = self.embeddings.copy()

        if document_id:
            indexes = [
                index
                for index, chunk in enumerate(chunks)
                if chunk["document_id"] == document_id
            ]

            if not indexes:
                return []

            filtered_chunks = [chunks[index] for index in indexes]
            filtered_embeddings = embeddings[indexes]
        else:
            filtered_chunks = chunks
            filtered_embeddings = embeddings

        query_vector = EMBED_MODEL.encode(
            query,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

        scores = filtered_embeddings @ query_vector
        top_indexes = np.argsort(scores)[::-1][:k]

        return [
            {
                **filtered_chunks[index],
                "score": round(float(scores[index]), 4),
            }
            for index in top_indexes
        ]

    def list_documents(self) -> list[dict]:
        with self._lock:
            documents = {}

            for chunk in self.chunks:
                document_id = chunk["document_id"]

                if document_id not in documents:
                    documents[document_id] = {
                        "document_id": document_id,
                        "filename": chunk["source"],
                        "chunks": 0,
                    }

                documents[document_id]["chunks"] += 1

            return sorted(
                documents.values(),
                key=lambda document: document["filename"].lower(),
            )


store = RagStore()


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "pdf-rag",
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def list_documents() -> list[dict]:
    """List PDFs currently indexed in the RAG store."""
    return store.list_documents()


@mcp.tool()
def search_docs(
    query: str,
    top_k: int = 4,
    document_id: str | None = None,
) -> list[dict]:
    """Search indexed PDFs and return relevant passages with page citations."""
    return store.search(query, top_k, document_id)


@mcp.tool()
def retrieve_pdf_context(
    question: str,
    top_k: int = 4,
    document_id: str | None = None,
) -> str:
    """Retrieve PDF context for the calling LLM to answer from."""
    hits = store.search(question, top_k, document_id)

    if not hits:
        return "No relevant PDF content was found."

    context = "\n\n---\n\n".join(
        f"[{hit['source']} p.{hit['page']} | score {hit['score']}]\n"
        f"{hit['text']}"
        for hit in hits
    )

    return (
        "Answer using only the context below. Cite the filename and page.\n\n"
        f"{context}\n\nQuestion: {question}"
    )


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_app.lifespan(app):
        yield


app = FastAPI(
    title="PDF RAG + MCP",
    lifespan=lifespan,
)

app.mount("/mcp", mcp_app)


@app.post("/upload")
async def upload_pdf(file: UploadFile = File(...)):
    filename = file.filename or "uploaded.pdf"

    if not filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are accepted",
        )

    data = await file.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="PDF exceeds the 20 MB limit",
        )

    if not data.startswith(b"%PDF-"):
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is not a valid PDF",
        )

    try:
        result = await run_in_threadpool(store.add_pdf, filename, data)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Unable to process PDF: {exc}",
        ) from exc

    if result["chunks_indexed"] == 0 and not result["duplicate"]:
        raise HTTPException(
            status_code=422,
            detail="No extractable text found. The PDF may require OCR.",
        )

    return {
        "file": filename,
        **result,
    }


@app.get("/documents")
def http_list_documents():
    return {"documents": store.list_documents()}


@app.get("/search")
def http_search(
    q: str = Query(min_length=1, max_length=2_000),
    k: int = Query(default=4, ge=1, le=MAX_RESULTS),
    document_id: str | None = None,
):
    results = store.search(q, k, document_id)

    return {
        "query": q,
        "result_count": len(results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        import uvicorn

        # Keep one worker because the vector store is in memory.
        uvicorn.run(app, host="0.0.0.0", port=8000, workers=1)
