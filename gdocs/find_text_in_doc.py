"""
Google Docs Text Finder with API Indices

New MCP tool: find_text_in_doc

Searches a Google Doc for text strings and returns their exact Google Docs API
startIndex and endIndex values. This enables precise format_text and link_url
operations without drift calculation.

Installation:
  1. Copy this file to gdocs/ in the google_workspace_mcp repo
  2. Register the tool in docs_tools.py (see REGISTRATION block at bottom)
  3. Redeploy the MCP server

Depends on: auth.service_decorator.require_google_service, core.server
"""

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: extract flat text map from raw Google Docs API response
# ---------------------------------------------------------------------------

def _build_text_index_map(doc_data: dict[str, Any], tab_id: Optional[str] = None) -> list[dict[str, Any]]:
    """
    Walk every paragraph → element → textRun in the document body and build
    a flat list of text segments with their API indices.

    Each entry:
        {
            "text": "Hello world\\n",
            "start_index": 1,
            "end_index": 13,
            "paragraph_start": 1,
            "paragraph_end": 13,
            "paragraph_style": "NORMAL_TEXT"
        }

    InlineObjectElements (images) are included with text="[image]" so the
    caller can see where they sit in the index space.
    """
    segments: list[dict[str, Any]] = []

    # Handle tabbed vs non-tabbed documents
    body_content = None
    if tab_id and "tabs" in doc_data:
        for tab in doc_data.get("tabs", []):
            tp = tab.get("tabProperties", {})
            if tp.get("tabId") == tab_id:
                body_content = (
                    tab.get("documentTab", {}).get("body", {}).get("content", [])
                )
                break
    if body_content is None:
        body_content = doc_data.get("body", {}).get("content", [])

    for element in body_content:
        if "paragraph" not in element:
            continue

        para = element["paragraph"]
        para_start = element.get("startIndex", 0)
        para_end = element.get("endIndex", 0)
        para_style = (
            para.get("paragraphStyle", {})
            .get("namedStyleType", "NORMAL_TEXT")
        )

        for pe in para.get("elements", []):
            if "textRun" in pe:
                tr = pe["textRun"]
                segments.append({
                    "text": tr.get("content", ""),
                    "start_index": pe.get("startIndex", 0),
                    "end_index": pe.get("endIndex", 0),
                    "paragraph_start": para_start,
                    "paragraph_end": para_end,
                    "paragraph_style": para_style,
                })
            elif "inlineObjectElement" in pe:
                segments.append({
                    "text": "[image]",
                    "start_index": pe.get("startIndex", 0),
                    "end_index": pe.get("endIndex", 0),
                    "paragraph_start": para_start,
                    "paragraph_end": para_end,
                    "paragraph_style": para_style,
                })

    return segments


def _concatenate_segments(segments: list[dict[str, Any]]) -> tuple[str, list[tuple[int, int]]]:
    """
    Concatenate all segment texts into a single string and build a mapping
    from string offset → API index.

    Returns:
        (full_text, offset_map)
        offset_map[i] = (api_start_index, segment_index) for character i in full_text
    """
    full_text = ""
    # Each entry: (string_offset, api_index, length)
    mappings: list[tuple[int, int, int]] = []

    for seg in segments:
        text = seg["text"]
        str_offset = len(full_text)
        api_start = seg["start_index"]
        mappings.append((str_offset, api_start, len(text)))
        full_text += text

    return full_text, mappings


def _find_matches(
    full_text: str,
    mappings: list[tuple[int, int, int]],
    segments: list[dict[str, Any]],
    search_text: str,
    match_case: bool = False,
    use_regex: bool = False,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """
    Find all occurrences of search_text in the concatenated document text
    and map each match back to API indices.
    """
    results: list[dict[str, Any]] = []

    flags = 0 if match_case else re.IGNORECASE
    if use_regex:
        pattern = re.compile(search_text, flags)
    else:
        pattern = re.compile(re.escape(search_text), flags)

    for m in pattern.finditer(full_text):
        if len(results) >= max_results:
            break

        match_str_start = m.start()
        match_str_end = m.end()

        # Map string offsets → API indices
        api_start = _str_offset_to_api_index(match_str_start, mappings)
        api_end = _str_offset_to_api_index(match_str_end, mappings)

        if api_start is not None and api_end is not None:
            # Find which paragraph this match is in
            para_start = None
            para_end = None
            para_style = None
            for seg in segments:
                if seg["start_index"] <= api_start < seg["end_index"]:
                    para_start = seg["paragraph_start"]
                    para_end = seg["paragraph_end"]
                    para_style = seg["paragraph_style"]
                    break

            results.append({
                "matched_text": m.group(),
                "api_start_index": api_start,
                "api_end_index": api_end,
                "paragraph_start_index": para_start,
                "paragraph_end_index": para_end,
                "paragraph_style": para_style,
            })

    return results


def _str_offset_to_api_index(
    str_offset: int,
    mappings: list[tuple[int, int, int]],
) -> Optional[int]:
    """Convert a string offset to the corresponding API index."""
    for seg_str_offset, seg_api_start, seg_len in mappings:
        seg_str_end = seg_str_offset + seg_len
        if seg_str_offset <= str_offset <= seg_str_end:
            delta = str_offset - seg_str_offset
            return seg_api_start + delta
    return None


# ---------------------------------------------------------------------------
# Public function: called by the MCP tool handler
# ---------------------------------------------------------------------------

def find_text_in_document(
    doc_data: dict[str, Any],
    search_text: str,
    match_case: bool = False,
    use_regex: bool = False,
    tab_id: Optional[str] = None,
    max_results: int = 50,
) -> str:
    """
    Search a Google Doc for text and return API indices for each match.

    Args:
        doc_data: Raw document data from documents().get()
        search_text: Plain text or regex pattern to find
        match_case: Whether to match case exactly (default: False)
        use_regex: Whether to interpret search_text as regex (default: False)
        tab_id: Optional tab ID to search within
        max_results: Maximum matches to return (default: 50)

    Returns:
        JSON string with match results
    """
    segments = _build_text_index_map(doc_data, tab_id)

    if not segments:
        return json.dumps({
            "error": "No text content found in document",
            "matches": [],
            "total_matches": 0,
        })

    full_text, mappings = _concatenate_segments(segments)
    matches = _find_matches(
        full_text, mappings, segments,
        search_text, match_case, use_regex, max_results,
    )

    # Also return document total_length for reference
    total_length = 0
    body_content = doc_data.get("body", {}).get("content", [])
    if body_content:
        last = body_content[-1]
        total_length = last.get("endIndex", 0)

    return json.dumps({
        "document_id": doc_data.get("documentId", ""),
        "document_title": doc_data.get("title", ""),
        "total_length": total_length,
        "search_text": search_text,
        "match_case": match_case,
        "use_regex": use_regex,
        "total_matches": len(matches),
        "matches": matches,
    }, indent=2)


# ---------------------------------------------------------------------------
# REGISTRATION — Add this to gdocs/docs_tools.py
# ---------------------------------------------------------------------------
#
# Import at top of docs_tools.py:
#
#   from gdocs.find_text_in_doc import find_text_in_document
#
# Then add the tool function:
#
#   @server.tool()
#   @require_google_service("docs", "docs_read")
#   async def find_text_in_doc(
#       service,
#       user_google_email: str,
#       document_id: str,
#       search_text: str,
#       match_case: bool = False,
#       use_regex: bool = False,
#       tab_id: Optional[str] = None,
#       max_results: int = 50,
#   ) -> str:
#       """Search a Google Doc for text and return exact API indices for each match.
#
#       This tool calls documents().get() to retrieve the full document structure,
#       then searches all text runs for the given string or regex pattern. Returns
#       the exact startIndex and endIndex (Google Docs API coordinates) for every
#       match, enabling precise format_text and link_url operations.
#
#       Unlike get_doc_content (plain text export) or inspect_doc_structure (which
#       returns 0 for docs with embedded images), this tool reads the raw API JSON
#       and returns deterministic indices.
#
#       Args:
#           service: Injected Google Docs API service client
#           user_google_email: User's Google email address
#           document_id: ID of the Google Doc to search
#           search_text: Text string or regex pattern to find
#           match_case: Whether to match case exactly (default: false)
#           use_regex: Whether to interpret search_text as a regex (default: false)
#           tab_id: Optional tab ID to restrict search to a specific tab
#           max_results: Maximum number of matches to return (default: 50)
#
#       Returns:
#           JSON string with all matches and their API index ranges. Each match:
#           - matched_text: the text that was found
#           - api_start_index: start index for format_text operations
#           - api_end_index: end index for format_text operations
#           - paragraph_start_index: start of the containing paragraph
#           - paragraph_end_index: end of the containing paragraph
#           - paragraph_style: named style of the containing paragraph
#       """
#       logger.info(
#           f"[find_text_in_doc] Email: {user_google_email}, "
#           f"Doc: {document_id}, Search: {search_text!r}"
#       )
#       doc_data = service.documents().get(
#           documentId=document_id,
#           includeTabsContent=True,
#       ).execute()
#       return find_text_in_document(
#           doc_data, search_text, match_case, use_regex, tab_id, max_results,
#       )
#
# ---------------------------------------------------------------------------
