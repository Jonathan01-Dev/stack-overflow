import os
import sys
import threading
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

# Rendre CORS optionnel
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass

# Import du service AI
try:
    sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai"))
    from gemini_service import GeminiService
except ImportError:
    GeminiService = None

# Référence globale au nœud Archipel
_node = None
_gemini = None
_ai_files_context = {}  # file_id -> content (RAG pool)

# Déterminer le chemin absolu du dossier 'web'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, 'web')

@app.route('/')
def index():
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/web/<path:path>')
def send_web_assets(path):
    return send_from_directory(WEB_DIR, path)

@app.route('/api/status')
def get_status():
    if not _node: return jsonify({"error": "Node not initialized"}), 500
    
    with _node.transfer_mgr.download_lock:
        downloads = []
        for fid, info in _node.transfer_mgr.active_downloads.items():
            downloads.append({
                "id": fid[:8],
                "filename": info["manifest"]["filename"],
                "progress": round((info["received_count"] / info["total_chunks"]) * 100, 1)
            })

    return jsonify({
        "node_id": _node.node_id,
        "tcp_port": os.environ.get("TCP_PORT", 7777),
        "downloads": downloads,
        "local_files_count": len(_node.storage_mgr.get_available_files())
    })

@app.route('/api/peers')
def get_peers():
    if not _node: return jsonify([]), 500
    peers_list = []
    with _node.connections_lock:
        for pid in _node.active_sessions:
            peer_info = _node.peer_table.get_peer(pid)
            peers_list.append({
                "id": pid,
                "short_id": pid[:16],
                "trusted": peer_info.get("trusted", False) if peer_info else False,
                "active": True
            })
    return jsonify(peers_list)

@app.route('/api/files')
def get_files():
    if not _node: return jsonify({}), 500
    
    network_files = []
    for fid, m in _node.network_manifests.items():
        network_files.append({
            "id": fid,
            "short_id": fid[:8],
            "filename": m['filename'],
            "size_kb": m['size'] // 1024,
            "is_local": False
        })
        
    local_files = []
    for fid, info in _node.storage_mgr.get_available_files().items():
        local_files.append({
            "id": fid,
            "short_id": fid[:8],
            "filename": info['manifest']['filename'],
            "size_kb": info['manifest']['size'] // 1024,
            "is_local": True
        })
        
    return jsonify({
        "network": network_files,
        "local": local_files
    })

@app.route('/api/msg', methods=['POST'])
def send_message():
    data = request.json
    target = data.get('target')
    text = data.get('text')
    
    if not target or not text:
        return jsonify({"success": False, "error": "Missing target or text"}), 400
        
    full_target = None
    with _node.connections_lock:
        active_pids = list(_node.active_sessions.keys())
        
    if target == "all":
        for pid in active_pids:
            _node.send_chat_message(pid, text)
        return jsonify({"success": True, "count": len(active_pids)})
    else:
        # Trouver par préfixe (car le front envoie souvent un short_id ou prefix)
        for pid in active_pids:
            if pid.startswith(target):
                full_target = pid
                break
        
        if full_target:
            _node.send_chat_message(full_target, text)
            return jsonify({"success": True, "target": full_target})
        else:
            return jsonify({"success": False, "error": f"Peer {target} not found"}), 404

@app.route('/api/messages/<pid>', methods=['GET'])
def get_messages(pid):
    if not _node: return jsonify([]), 500
    
    # Trouver le peer_id complet si c'est un préfixe
    full_pid = None
    with _node.connections_lock:
        for apid in _node.active_sessions:
            if apid.startswith(pid):
                full_pid = apid
                break
    
    if not full_pid: return jsonify([])
    
    with _node.history_lock:
        history = _node.message_history.get(full_pid, [])
        return jsonify(history)

@app.route('/api/trust/<pid>', methods=['POST'])
def trust_peer(pid):
    if not _node: return jsonify({"success": False}), 500
    try:
        _node.peer_table.trust_peer(pid)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/download/<prefix>', methods=['POST'])
def start_download(prefix):
    target_fid = None
    for fid in _node.network_manifests:
        if fid.startswith(prefix):
            target_fid = fid
            break
    
    if target_fid:
        _node.transfer_mgr.start_download(target_fid)
        return jsonify({"success": True, "file_id": target_fid})
    else:
        return jsonify({"success": False, "error": "File not found"}), 404

# --- API AI (Sprint 4.2) ---

@app.route('/api/ai/ask', methods=['POST'])
def ai_ask():
    if not _gemini or not _gemini.enabled:
        return jsonify({"success": False, "error": "IA désactivée ou non configurée."}), 400
    
    data = request.json
    peer_id = data.get('peer_id')  # Contexte de discussion
    query = data.get('query')
    
    if not query:
        return jsonify({"success": False, "error": "Question manquante."}), 400
        
    # 1. Récupérer l'historique de discussion (N derniers messages)
    history = []
    if peer_id:
        with _node.history_lock:
            history = _node.message_history.get(peer_id, [])[-10:] # 10 derniers
            
    # 2. Préparer le contexte des fichiers (RAG)
    files_context = {}
    for fid, content in _ai_files_context.items():
        # On pourrait limiter la taille ici
        files_context[fid[:8]] = content
        
    # 3. Appeler Gemini
    result = _gemini.query(history, query, files_context)
    
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
        
    return jsonify({"success": True, "response": result["text"]})

@app.route('/api/ai/index_file/<fid>', methods=['POST'])
def ai_index_file(fid):
    if not _node: return jsonify({"success": False}), 500
    if not _gemini or not _gemini.enabled:
        return jsonify({"success": False, "error": "L'IA n'est pas activée."}), 400
    
    # Trouver le fichier localement
    local_files = _node.storage_mgr.get_available_files()
    if fid not in local_files:
        return jsonify({"success": False, "error": "Fichier non trouvé localement."}), 404
        
    file_info = local_files[fid]
    path = file_info["local_path"]
    filename = file_info["manifest"]["filename"]
    
    if not path or not os.path.exists(path):
        return jsonify({"success": False, "error": "Chemin du fichier invalide."}), 400
        
    try:
        # Envoyer via l'API File Gemini (chunked upload API REST)
        res = _gemini.upload_file_chunked(path, display_name=filename)
        
        if "error" in res:
            return jsonify({"success": False, "error": res["error"]}), 500
            
        # L'API Gemini retourne un objet `file`
        if "file" in res and "uri" in res["file"]:
            gemini_uri = res["file"]["uri"]
            mime_type = res["file"].get("mimeType", "application/octet-stream")
            
            # Stocker l'URI et le mimetype à la place du contenu brut
            _ai_files_context[fid] = {
                "type": "gemini_file",
                "fileUri": gemini_uri,
                "mimeType": mime_type,
                "filename": filename
            }
            return jsonify({"success": True, "indexed": True, "uri": gemini_uri})
        else:
            return jsonify({"success": False, "error": "Format de réponse inattendu de Gemini."}), 500
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400
    
    # Sauvegarder temporairement pour partager
    temp_path = os.path.join(os.getcwd(), file.filename)
    file.save(temp_path)
    
    try:
        _node.share_file(temp_path)
        return jsonify({"success": True, "filename": file.filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/settings/api_key', methods=['POST'])
def save_api_key():
    """Sauvegarde la clé API Gemini dans le fichier .env du projet."""
    data = request.json
    key = data.get('api_key', '').strip()
    if not key:
        return jsonify({"success": False, "error": "Clé vide."}), 400
    try:
        # Trouver le .env à la racine du projet (deux niveaux au-dessus de web_server.py)
        project_root = os.path.dirname(os.path.dirname(BASE_DIR))
        env_path = os.path.join(project_root, '.env')
        
        # Lire le .env existant
        lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                lines = f.readlines()
        
        # Remplacer ou ajouter GEMINI_API_KEY
        found = False
        for i, line in enumerate(lines):
            if line.startswith('GEMINI_API_KEY='):
                lines[i] = f'GEMINI_API_KEY={key}\n'
                found = True
                break
        if not found:
            lines.append(f'GEMINI_API_KEY={key}\n')
        
        with open(env_path, 'w') as f:
            f.writelines(lines)
        
        # Mettre à jour le service en mémoire immédiatement
        if _gemini:
            _gemini.api_key = key
            _gemini.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{_gemini.model}:generateContent?key={key}"
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def start_web_server(node, port=8080):
    global _node, _gemini
    _node = node
    
    # Initialisation Gemini
    if GeminiService:
        _gemini = GeminiService(api_key=node.ai_key, enabled=node.ai_enabled)
    # Désactiver le log de Flask pour ne pas polluer la console du noeud
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Vérifier l'existence du dossier 'web'
    if not os.path.exists(WEB_DIR):
        print(f"\033[91m[!] Erreur Web Server : Dossier {WEB_DIR} introuvable.\033[0m")
        return

    print(f"\033[92m[+] Dashboard Web accessible sur http://localhost:{port}\033[0m")
    app.run(host='0.0.0.0', port=port, threaded=True, use_reloader=False)
