from flask import Flask, request, jsonify
import secrets
import hashlib
import hmac

app = Flask(__name__)
entities = {}
secret_key = secrets.token_bytes(32)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    entity_id = data.get('entity_id')
    entity_type = data.get('entity_type')

    if not entity_id or not entity_type:
        return jsonify({"error": "missing entity_id/entitytype"}), 400

    if entity_id in entities:
        return jsonify({"error": "entity already registered"}), 409

    session_key = secrets.token_bytes(32)
    entities[entity_id] = {
        "type": entity_type,
        "session_key": session_key.hex(),
        "status": "active"
    }

    return jsonify({
        "session_key": session_key.hex(),
        "message": "registration successful"
    }), 201

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    entity_id = data.get('entity_id')
    nonce = data.get('nonce')
    received_hmac = data.get('hmac')

    if not all([entity_id, nonce, received_hmac]):
        return jsonify({"error": "missing authentication parameters"}), 400

    entity = entities.get(entity_id)
    if not entity:
        return jsonify({"error": "unknown entity"}), 404

    session_key = bytes.fromhex(entity['session_key'])
    valid_hmac = hmac.new(session_key, nonce.encode(), hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(received_hmac, valid_hmac):
        return jsonify({"status": "authenticated"}), 200
    else:
        return jsonify({"error": "authentication failed"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6000)
