from pathlib import Path
import json
from uuid import uuid4
import pytest
from app.sapper_integration import (
    SCRIPT, GraphError, graph_store, initialize_graph, public_graph, stage_begin, stage_end
)

def test_vendored_sapper_v2_exists():
    assert SCRIPT.is_file(), "Pinned real Sapper-v2 CLI must be committed"

def test_facts_and_intents_use_upstream_sapper(tmp_path):
    eid = str(uuid4())
    anchor = initialize_graph(eid, tmp_path)
    assert anchor.startswith("f")
    intent = stage_begin(eid, tmp_path, "Recon Agent", anchor)
    assert intent.startswith("i")
    pending = public_graph(eid, tmp_path)
    assert len(pending["intents"]) == 1
    assert pending["intents"][0]["status"] == "open"
    assert pending["intents"][0]["to"] is None
    result = stage_end(eid, tmp_path, "Recon Agent", intent, "Recon completed with 2 service ports")
    assert result.startswith("f")
    done = public_graph(eid, tmp_path)
    assert done["intents"][0]["to"] == result
    assert done["intents"][0]["status"] == "done"
    assert done["engine"].startswith("N1nEmAn/sapper-v2")
    persisted = graph_store(eid, tmp_path) / "project.json"
    assert persisted.is_file()
    text = "".join(path.read_text() for path in persisted.parent.rglob("*.json"))
    assert "192.0.2.10" not in text

def test_reject_path_escape_and_unexpected_descriptions(tmp_path):
    with pytest.raises(GraphError):
        graph_store("../../etc", tmp_path)
    eid = str(uuid4())
    root = initialize_graph(eid, tmp_path)
    with pytest.raises(GraphError):
        stage_begin(eid, tmp_path, "Recon; rm -rf", root)
    intent = stage_begin(eid, tmp_path, "Recon Agent", root)
    with pytest.raises(GraphError):
        stage_end(eid, tmp_path, "Recon Agent", intent, "Authorization: Bearer abcdefghijk")
