"""
PDF RAG using FastAPI + MCP + BM25.

Install:
    pip install "mcp[cli]" fastapi uvicorn pypdf \
        rank-bm25 python-multipart

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

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader
from rank_bm25 import BM25Okapi
from starlette.concurrency import run_in_threadpool

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_PAGES = 300
MAX_RESULTS = 20

CHUNK_SIZE = 1_000
CHUNK_OVERLAP = 150


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def tokenize(text: str) -> list[str]:
    """
    Simple tokenizer for BM25.

    Keeps letters, numbers, underscores and hyphens so identifiers such as
    POL-2026-001 or customer_id remain searchable.
    """
    return re.findall(r"[a-zA-Z0-9_-]+", text.lower())


def chunk_text(text: str) -> list[str]:
    chunks: list[str] = []
    start = 0

    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        piece = text[start:end]

        # Try to end at a sentence or paragraph boundary.
        if end < len(text):
            boundary = max(
                piece.rfind("\n\n"),
                piece.rfind(". "),
                piece.rfind("? "),
                piece.rfind("! "),
            )

            if boundary > CHUNK_SIZE // 2:
                piece = piece[: boundary + 1]
                end = start + len(piece)

        piece = piece.strip()

        if piece:
            chunks.append(piece)

        next_start = end - CHUNK_OVERLAP
        start = max(next_start, start + 1)

    return chunks


# ---------------------------------------------------------------------------
# In-memory BM25 RAG store
# ---------------------------------------------------------------------------

class RagStore:
    def __init__(self):
        self._lock = RLock()

        self.chunks: list[dict] = []
        self.tokenized_chunks: list[list[str]] = []
        self.document_ids: set[str] = set()
        self.bm25: BM25Okapi | None = None

    def _rebuild_index(self) -> None:
        """
        Rebuild BM25 whenever documents are added or removed.

        This is acceptable for a small demo. For a large collection,
        use a persistent search engine such as OpenSearch or Elasticsearch.
        """
        self.bm25 = (
            BM25Okapi(self.tokenized_chunks)
            if self.tokenized_chunks
            else None
        )

    def add_pdf(self, filename: str, data: bytes) -> dict:
        document_id = hashlib.sha256(data).hexdigest()

        with self._lock:
            if document_id in self.document_ids:
                return {
                    "document_id": document_id,
                    "chunks_indexed": 0,
                    "duplicate": True,
                    "pages_without_text": 0,
                    "total_pages": 0,
                }

        reader = PdfReader(io.BytesIO(data))

        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported")

        total_pages = len(reader.pages)

        if total_pages > MAX_PAGES:
            raise ValueError(
                f"PDF exceeds the {MAX_PAGES}-page limit"
            )

        new_chunks: list[dict] = []
        new_tokenized_chunks: list[list[str]] = []
        pages_without_text = 0

        for page_number, page in enumerate(reader.pages, start=1):
            text = normalize_text(page.extract_text() or "")

            if not text:
                pages_without_text += 1
                continue

            for chunk_index, piece in enumerate(chunk_text(text)):
                tokens = tokenize(piece)

                if not tokens:
                    continue

                new_chunks.append(
                    {
                        "document_id": document_id,
                        "source": filename,
                        "page": page_number,
                        "chunk_index": chunk_index,
                        "text": piece,
                    }
                )
                new_tokenized_chunks.append(tokens)

        if not new_chunks:
            return {
                "document_id": document_id,
                "chunks_indexed": 0,
                "duplicate": False,
                "pages_without_text": pages_without_text,
                "total_pages": total_pages,
            }

        with self._lock:
            # Check again in case two requests uploaded the same file together.
            if document_id in self.document_ids:
                return {
                    "document_id": document_id,
                    "chunks_indexed": 0,
                    "duplicate": True,
                    "pages_without_text": pages_without_text,
                    "total_pages": total_pages,
                }

            self.chunks.extend(new_chunks)
            self.tokenized_chunks.extend(new_tokenized_chunks)
            self.document_ids.add(document_id)
            self._rebuild_index()

        return {
            "document_id": document_id,
            "chunks_indexed": len(new_chunks),
            "duplicate": False,
            "pages_without_text": pages_without_text,
            "total_pages": total_pages,
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

        query_tokens = tokenize(query)

        if not query_tokens:
            return []

        k = max(1, min(k, MAX_RESULTS))

        with self._lock:
            if not self.chunks or self.bm25 is None:
                return []

            chunks = list(self.chunks)
            tokenized_chunks = list(self.tokenized_chunks)

        if document_id:
            matching_indexes = [
                index
                for index, chunk in enumerate(chunks)
                if chunk["document_id"] == document_id
            ]

            if not matching_indexes:
                return []

            filtered_chunks = [
                chunks[index]
                for index in matching_indexes
            ]
            filtered_tokens = [
                tokenized_chunks[index]
                for index in matching_indexes
            ]

            search_index = BM25Okapi(filtered_tokens)
        else:
            filtered_chunks = chunks

            with self._lock:
                if self.bm25 is None:
                    return []

                search_index = self.bm25

        scores = search_index.get_scores(query_tokens)

        ranked_indexes = sorted(
            range(len(scores)),
            key=lambda index: scores[index],
            reverse=True,
        )

        results = []

        for index in ranked_indexes:
            score = float(scores[index])

            # BM25 can return zero for chunks with no matching terms.
            if score <= 0:
                continue

            results.append(
                {
                    **filtered_chunks[index],
                    "score": round(score, 4),
                }
            )

            if len(results) >= k:
                break

        return results

    def list_documents(self) -> list[dict]:
        with self._lock:
            documents: dict[str, dict] = {}

            for chunk in self.chunks:
                document_id = chunk["document_id"]

                if document_id not in documents:
                    documents[document_id] = {
                        "document_id": document_id,
                        "filename": chunk["source"],
                        "chunks": 0,
                        "pages": set(),
                    }

                documents[document_id]["chunks"] += 1
                documents[document_id]["pages"].add(chunk["page"])

            response = []

            for document in documents.values():
                response.append(
                    {
                        "document_id": document["document_id"],
                        "filename": document["filename"],
                        "chunks": document["chunks"],
                        "pages_with_text": len(document["pages"]),
                    }
                )

            return sorted(
                response,
                key=lambda item: item["filename"].lower(),
            )

    def delete_document(self, document_id: str) -> bool:
        with self._lock:
            indexes_to_keep = [
                index
                for index, chunk in enumerate(self.chunks)
                if chunk["document_id"] != document_id
            ]

            if len(indexes_to_keep) == len(self.chunks):
                return False

            self.chunks = [
                self.chunks[index]
                for index in indexes_to_keep
            ]
            self.tokenized_chunks = [
                self.tokenized_chunks[index]
                for index in indexes_to_keep
            ]

            self.document_ids.discard(document_id)
            self._rebuild_index()

            return True


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
    """List PDF documents currently indexed in the BM25 store."""
    return store.list_documents()


@mcp.tool()
def search_docs(
    query: str,
    top_k: int = 4,
    document_id: str | None = None,
) -> list[dict]:
    """
    Search indexed PDFs using BM25 keyword ranking.

    Returns matching chunks with filename, page number and BM25 score.
    """
    return store.search(
        query=query,
        k=top_k,
        document_id=document_id,
    )


@mcp.tool()
def retrieve_pdf_context(
    question: str,
    top_k: int = 4,
    document_id: str | None = None,
) -> str:
    """
    Retrieve relevant PDF passages for the calling LLM.

    The calling LLM should answer only from the returned context and cite
    the PDF filename and page number.
    """
    hits = store.search(
        query=question,
        k=top_k,
        document_id=document_id,
    )

    if not hits:
        return (
            "No relevant PDF content was found. "
            "The question may use different wording from the document."
        )

    context = "\n\n---\n\n".join(
        (
            f"[{hit['source']} p.{hit['page']} "
            f"| BM25 score {hit['score']}]\n"
            f"{hit['text']}"
        )
        for hit in hits
    )

    return (
        "Answer using only the context below. "
        "Cite the PDF filename and page number.\n\n"
        f"{context}\n\n"
        f"Question: {question}"
    )


@mcp.tool()
def delete_document(document_id: str) -> str:
    """Delete a PDF and all its indexed chunks."""
    deleted = store.delete_document(document_id)

    if not deleted:
        return f"Document not found: {document_id}"

    return f"Document deleted: {document_id}"


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_app.lifespan(app):
        yield


app = FastAPI(
    title="PDF RAG with BM25 + MCP",
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
        result = await run_in_threadpool(
            store.add_pdf,
            filename,
            data,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Unable to process PDF: {exc}",
        ) from exc

    if result["chunks_indexed"] == 0 and not result["duplicate"]:
        raise HTTPException(
            status_code=422,
            detail=(
                "No extractable text found. "
                "The PDF may require OCR."
            ),
        )

    return {
        "file": filename,
        **result,
    }


@app.get("/documents")
def http_list_documents():
    return {
        "documents": store.list_documents(),
    }


@app.get("/search")
def http_search(
    q: str = Query(min_length=1, max_length=2_000),
    k: int = Query(default=4, ge=1, le=MAX_RESULTS),
    document_id: str | None = None,
):
    results = store.search(
        query=q,
        k=k,
        document_id=document_id,
    )

    return {
        "query": q,
        "result_count": len(results),
        "results": results,
    }


@app.delete("/documents/{document_id}")
def http_delete_document(document_id: str):
    deleted = store.delete_document(document_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    return {
        "document_id": document_id,
        "deleted": True,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        import uvicorn

        # Keep one worker because the BM25 index is stored in memory.
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            workers=1,
        )
