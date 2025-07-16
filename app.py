from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, abort
import os
import re
import difflib
import requests
import json
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from cachetools import cached, TTLCache
from bs4 import BeautifulSoup
import zipfile
from threading import Lock
from datetime import datetime
import time
import uuid
import threading
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
import secrets
import hashlib
import urllib.parse
from werkzeug.utils import secure_filename
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
import tempfile
import shutil
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/patchleaks.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('PatchLeaks startup')

ALLOWED_EXTENSIONS = frozenset(['.txt', '.py', '.js', '.html', '.css', '.json', '.md', '.xml', '.yaml', '.yml', '.php', '.java', '.cpp', '.c', '.h', '.go', '.rs', '.rb', '.sql', '.sh', '.bat', '.tsx', '.ts', '.vue', '.jsx'])
VALID_AI_SERVICES = frozenset(['ollama', 'openai', 'deepseek', 'claude'])
VALID_SOURCES = frozenset(['library_auto', 'products', 'folder', 'direct'])

ai_cache = TTLCache(maxsize=1000000000, ttl=0)
VERSION_CACHE = TTLCache(maxsize=100, ttl=0)
version_lock = Lock()

PRODUCTS_DIR = os.path.join(os.path.dirname(__file__), 'products')
AI_CONFIG_FILE = 'ai_config.json'
PRODUCTS_FILE = os.path.join(PRODUCTS_DIR, 'products.json')
LIBRARY_FILE = os.path.join(PRODUCTS_DIR, 'library.json')
SAVED_ANALYSES_DIR = os.path.join(os.path.dirname(__file__), 'saved_analyses')

os.makedirs(SAVED_ANALYSES_DIR, exist_ok=True)
os.chmod(SAVED_ANALYSES_DIR, 0o755)

scheduler = BackgroundScheduler()
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def get_safe_path(base_dir, user_path):
    try:
        base_path = Path(base_dir).resolve()
        clean_path = secure_filename(str(user_path)) if user_path else ""
        if not clean_path:
            return None
        full_path = (base_path / clean_path).resolve()
        return str(full_path) if str(full_path).startswith(str(base_path)) else None
    except Exception:
        return None

def is_allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def validate_input(input_str, max_length=1000, pattern=None):
    if not input_str:
        return ""
    clean_input = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(input_str))
    if len(clean_input) > max_length:
        clean_input = clean_input[:max_length]
    if pattern and not re.match(pattern, clean_input):
        return ""
    return clean_input.strip()

def validate_url(url):
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        return (parsed.scheme in ['http', 'https'] and 
                parsed.netloc in ['github.com', 'www.github.com'] and
                len(parsed.path) > 1)
    except Exception:
        return False

def validate_version(version):
    if not version:
        return False
    return re.match(r'^[a-zA-Z0-9._-]+$', version) and len(version) <= 50

def validate_filename(filename):
    if not filename:
        return False
    return '..' not in filename and not filename.startswith('/') and ':' not in filename and is_allowed_file(filename) and len(filename) <= 255

def validate_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False

def load_json_safe(filepath, default=None):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, (dict, list)) else default
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return default

def save_json_safe(filepath, data):
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Failed to save {filepath}: {str(e)}")
        return False

def load_library():
    data = load_json_safe(LIBRARY_FILE, [])
    return [repo for repo in data if isinstance(repo, dict)] if isinstance(data, list) else []

def save_library(library_data):
    if not isinstance(library_data, list):
        raise ValueError("Invalid library data format")
    if not save_json_safe(LIBRARY_FILE, library_data):
        raise Exception("Failed to save library data")

def add_library_repo(name, repo_url, ai_service):
    name = validate_input(name, 100, r'^[a-zA-Z0-9._-]+$')
    if not name:
        return False, "Invalid repository name"
    if not validate_url(repo_url):
        return False, "Invalid repository URL"
    ai_service = ai_service if ai_service in VALID_AI_SERVICES else 'ollama'
    
    library = load_library()
    if any(repo.get('name') == name for repo in library):
        return False, "Repository already exists"
    
    library.append({
        'id': str(uuid.uuid4()),
        'name': name,
        'repo_url': repo_url,
        'ai_service': ai_service,
        'created_at': datetime.now().isoformat(),
        'last_checked': None,
        'last_version': None,
        'auto_scan': True
    })
    
    save_library(library)
    return True, "Repository added successfully"

def remove_library_repo(repo_id):
    if not validate_uuid(repo_id):
        return False
    library = load_library()
    library = [repo for repo in library if repo.get('id') != repo_id]
    save_library(library)
    return True

def update_library_repo(repo_id, **kwargs):
    if not validate_uuid(repo_id):
        return False
    library = load_library()
    allowed_fields = frozenset(['last_checked', 'last_version', 'auto_scan'])
    for repo in library:
        if repo.get('id') == repo_id:
            for key, value in kwargs.items():
                if key in allowed_fields:
                    repo[key] = value
            break
    save_library(library)
    return True

def check_for_new_versions():
    try:
        app.logger.info("Checking for new versions in library")
        library = load_library()
        
        for repo in library:
            if not repo.get('auto_scan', True):
                continue
            
            try:
                repo_url = repo.get('repo_url')
                if not validate_url(repo_url):
                    continue
                
                versions = get_github_versions(repo_url)
                if versions:
                    latest_version = versions[0]
                    if repo.get('last_version') != latest_version:
                        app.logger.info(f"New version detected for {repo.get('name')}: {latest_version}")
                        update_library_repo(repo['id'], 
                                          last_version=latest_version,
                                          last_checked=datetime.now().isoformat())
                        if repo.get('last_version') is not None:
                            trigger_auto_analysis(repo, repo['last_version'], latest_version)
                        else:
                            update_library_repo(repo['id'], last_version=latest_version)
                    else:
                        update_library_repo(repo['id'], last_checked=datetime.now().isoformat())
            except Exception as e:
                app.logger.error(f"Error checking versions for {repo.get('name')}: {str(e)}")
    except Exception as e:
        app.logger.error(f"Error in check_for_new_versions: {str(e)}")

def trigger_auto_analysis(repo, old_version, new_version):
    try:
        if not validate_version(old_version) or not validate_version(new_version):
            return
        
        params = {
            'repo_name': validate_input(repo.get('name', ''), 100),
            'repo_url': repo.get('repo_url'),
            'old_version': old_version,
            'new_version': new_version,
            'ai_service': validate_input(repo.get('ai_service', 'ollama'), 50),
            'extension': '',
            'enable_ai': 'on',
            'special_keywords': 'security,vulnerability,fix,patch,cve,exploit,auth,password,sql,xss,csrf',
            'cve_ids': ''
        }
        
        analysis_id = create_new_analysis_record(params, source='library_auto', ai_enabled=True)
        threading.Thread(target=run_library_analysis_background, args=(analysis_id, params)).start()
        app.logger.info(f"Auto-analysis triggered for {repo.get('name')} ({old_version} → {new_version})")
    except Exception as e:
        app.logger.error(f"Failed to trigger auto-analysis for {repo.get('name')}: {str(e)}")

def create_new_analysis_record(params, source, ai_enabled):
    analysis_id = str(uuid.uuid4())
    source = source if source in VALID_SOURCES else 'direct'
    
    analysis_data = {
        'meta': {
            'created_at': datetime.now().isoformat(),
            'source': source,
            'ai_enabled': bool(ai_enabled),
            'params': params,
            'status': 'running'
        },
        'results': {}
    }
    
    analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
    try:
        with open(analysis_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        os.chmod(analysis_path, 0o644)
    except Exception as e:
        app.logger.error(f"Failed to create analysis record: {str(e)}")
        raise
    
    return analysis_id

def run_library_analysis_background(analysis_id, params):
    try:
        analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
        repo_name = params['repo_name']
        repo_url = params['repo_url']
        old_ver = params['old_version']
        new_ver = params['new_version']

        product_name = repo_name.lower().replace('.', '').replace(' ', '').replace('-', '').replace('_', '')
        download_dir = os.path.join(PRODUCTS_DIR, f"{product_name}_downloads")
        product_versions_file = os.path.join(PRODUCTS_DIR, f"{product_name}.json")
        os.makedirs(download_dir, exist_ok=True)

        versions = load_json_safe(product_versions_file, [])

        for ver in [old_ver, new_ver]:
            if not any(v['version'] == ver for v in versions):
                try:
                    zip_url = f"{repo_url}/archive/refs/tags/{ver}.zip"
                    response = requests.get(zip_url, stream=True)
                    response.raise_for_status()

                    zip_path = os.path.join(download_dir, f"{ver}.zip")
                    extract_path = os.path.join(download_dir, ver)

                    with open(zip_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_path)

                    os.remove(zip_path)
                    final_path = os.path.join(extract_path, os.listdir(extract_path)[0])

                    versions.append({
                        'version': ver,
                        'path': final_path,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return

        save_json_safe(product_versions_file, versions)

        old_path = next(v['path'] for v in versions if v['version'] == old_ver)
        new_path = next(v['path'] for v in versions if v['version'] == new_ver)

        compare_folders(old_path, new_path, params.get('extension'), 
                       params['special_keywords'].split(',') if params['special_keywords'] else None)
        diffs = parse_diff_file("special.txt")
        analyzed_results = analyze_diffs_with_keywords(diffs, 
                                                     params['special_keywords'].split(',') if params['special_keywords'] else None)

        if params['enable_ai'] == 'on' and analyzed_results:
            original_config = load_ai_config()
            temp_config = original_config.copy()
            temp_config['service'] = params['ai_service']

            with open(AI_CONFIG_FILE, 'w') as f:
                json.dump(temp_config, f)

            try:
                analyzed_results = process_ai_analysis(analyzed_results, diffs, params['cve_ids'])
            finally:
                with open(AI_CONFIG_FILE, 'w') as f:
                    json.dump(original_config, f)

        with open(analysis_path, 'r') as f:
            analysis_data = json.load(f)

        analysis_data['meta']['status'] = 'completed'
        analysis_data['results'] = analyzed_results
        with open(analysis_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)

        app.logger.info(f"Auto-analysis completed for {repo_name}")

    except Exception as e:
        try:
            with open(analysis_path, 'r') as f:
                analysis_data = json.load(f)
            analysis_data['meta']['status'] = 'failed'
            analysis_data['meta']['error'] = str(e)
            with open(analysis_path, 'w') as f:
                json.dump(analysis_data, f, indent=2)
        except:
            pass

scheduler.add_job(
    func=check_for_new_versions,
    trigger=IntervalTrigger(minutes=30),
    id='version_checker',
    name='Check for new versions',
    replace_existing=True
)

def load_ai_config():
    default = {
        'service': 'ollama',
        'ollama': {'url': 'http://localhost:11434', 'model': 'qwen2.5-coder:3b'},
        'openai': {'key': '', 'model': 'gpt-4-turbo', 'base_url': 'https://api.openai.com/v1'},
        'deepseek': {'key': '', 'model': 'deepseek-coder-33b-instruct', 'base_url': 'https://api.deepseek.com/v1'},
        'claude': {'key': '', 'model': 'claude-3-opus-20240229', 'base_url': 'https://api.anthropic.com/v1'},
        'parameters': {'temperature': 1.0, 'num_ctx': 8192}
    }
    
    config = load_json_safe(AI_CONFIG_FILE, default)
    if not isinstance(config, dict):
        return default
    
    for service in ['openai', 'deepseek', 'claude']:
        if service not in config:
            config[service] = default[service]
        else:
            for key, value in default[service].items():
                if key not in config[service] or config[service][key] is None:
                    config[service][key] = value
    return config

@cached(ai_cache)
def get_ai_analysis(file_path, diff_content):
    config = load_ai_config()
    prompt = f"Analyze the provided code diff for security fixes.\n\nInstructions:\n1. Your answer MUST strictly follow the answer format outlined below.\n2. Always include the vulnerability name if one exists.\n3. There may be multiple vulnerabilities. For each, provide a separate entry following the structure.\n4. Even if you are uncertain whether a vulnerability exists, follow the structure and indicate your uncertainty.\n\nAnswer Format for Each Vulnerability:\n    Vulnerability Existed: [yes/no/not sure]\n    [Vulnerability Name] [File] [Lines]\n    [Old Code]\n    [Fixed Code]\n\nAdditional Details:\n    File: {file_path}\n    Diff Content:\n    {diff_content}"
    
    retry_count = 0
    while retry_count < 3:
        try:
            if config['service'] == 'ollama':
                response = requests.post(
                    f"{config['ollama']['url']}/api/generate",
                    json={
                        'model': config['ollama']['model'],
                        'prompt': prompt,
                        'stream': False,
                        'options': {'temperature': config['parameters']['temperature'], 'num_ctx': config['parameters']['num_ctx']}
                    },
                    timeout=999999
                )
            elif config['service'] == 'openai':
                response = requests.post(
                    f"{config['openai']['base_url']}/chat/completions",
                    headers={'Authorization': f"Bearer {config['openai']['key']}"},
                    json={
                        'model': config['openai']['model'],
                        'messages': [{'role': 'user', 'content': prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
            elif config['service'] == 'deepseek':
                response = requests.post(
                    f"{config['deepseek']['base_url']}/chat/completions",
                    headers={'Authorization': f"Bearer {config['deepseek']['key']}"},
                    json={
                        'model': config['deepseek']['model'],
                        'messages': [{'role': 'user', 'content': prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
            elif config['service'] == 'claude':
                response = requests.post(
                    f"{config['claude']['base_url']}/messages",
                    headers={'x-api-key': config['claude']['key'], 'anthropic-version': '2023-06-01'},
                    json={
                        'model': config['claude']['model'],
                        'max_tokens': config['parameters']['num_ctx'],
                        'temperature': config['parameters']['temperature'],
                        'messages': [{'role': 'user', 'content': prompt}]
                    },
                    timeout=999999
                )
            else:
                return "Invalid AI service configuration"
            
            if response.status_code == 429:
                retry_count += 1
                time.sleep(min(2 ** retry_count, 60))
                continue
            
            if config['service'] == 'ollama':
                return response.json().get('response', 'No AI response') if response.ok else f"Error: {response.text}"
            elif config['service'] in ['openai', 'deepseek']:
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
            elif config['service'] == 'claude':
                return response.json()['content'][0]['text'] if response.ok else f"Error: {response.text}"
                
        except Exception as e:
            if hasattr(e, 'response') and getattr(e.response, 'status_code', None) == 429:
                retry_count += 1
                time.sleep(min(2 ** retry_count, 60))
                continue
            return f"Connection failed: {str(e)}"

def get_cve_description(cve_id):
    try:
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"}
        response = requests.get(url, timeout=60, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        description_tag = soup.find('p', {'data-testid': 'vuln-description'})
        return description_tag.text.strip() if description_tag else "No description found"
    except Exception as e:
        return f"Failed to fetch CVE description: {str(e)}"

def analyze_with_cve(ai_response, cve_description):
    analysis_prompt = f"Analysis:\n{ai_response}\nQuestion: Do any of the vulnerabilities identified in the analysis match the description?\nReply strictly in this format: 'Description Matches: Yes/No' \nDescription:{cve_description}"
    
    retry_count = 0
    while retry_count < 3:
        try:
            config = load_ai_config()
            if config['service'] == 'ollama':
                response = requests.post(
                    f"{config['ollama']['url']}/api/generate",
                    json={
                        'model': config['ollama']['model'],
                        'prompt': analysis_prompt,
                        'stream': False,
                        'options': {'temperature': config['parameters']['temperature'], 'num_ctx': config['parameters']['num_ctx']}
                    },
                    timeout=999999
                )
            elif config['service'] == 'openai':
                response = requests.post(
                    f"{config['openai']['base_url']}/chat/completions",
                    headers={'Authorization': f"Bearer {config['openai']['key']}"},
                    json={
                        'model': config['openai']['model'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
            elif config['service'] == 'deepseek':
                response = requests.post(
                    f"{config['deepseek']['base_url']}/chat/completions",
                    headers={'Authorization': f"Bearer {config['deepseek']['key']}"},
                    json={
                        'model': config['deepseek']['model'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
            elif config['service'] == 'claude':
                response = requests.post(
                    f"{config['claude']['base_url']}/messages",
                    headers={'x-api-key': config['claude']['key'], 'anthropic-version': '2023-06-01'},
                    json={
                        'model': config['claude']['model'],
                        'max_tokens': config['parameters']['num_ctx'],
                        'temperature': config['parameters']['temperature'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}]
                    },
                    timeout=999999
                )
            else:
                return "CVE analysis failed: Unsupported AI service"
            
            if response.status_code == 429:
                retry_count += 1
                time.sleep(min(2 ** retry_count, 60))
                continue
            
            if config['service'] == 'ollama':
                return response.json().get('response', 'No AI response') if response.ok else f"Error: {response.text}"
            elif config['service'] in ['openai', 'deepseek']:
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
            elif config['service'] == 'claude':
                return response.json()['content'][0]['text'] if response.ok else f"Error: {response.text}"
                
        except Exception as e:
            if hasattr(e, 'response') and getattr(e.response, 'status_code', None) == 429:
                retry_count += 1
                time.sleep(min(2 ** retry_count, 60))
                continue
            return f"CVE analysis error: {str(e)}"

def extract_context(diff_lines, match_indices, context=15):
    intervals = []
    for idx in match_indices:
        start = max(0, idx - context)
        end = min(len(diff_lines) - 1, idx + context)
        intervals.append((start, end))
    intervals.sort()
    
    merged = []
    for interval in intervals:
        if not merged or interval[0] > merged[-1][1] + 1:
            merged.append(list(interval))
        else:
            merged[-1][1] = max(merged[-1][1], interval[1])
    
    result_lines = []
    for i, (start, end) in enumerate(merged):
        if i > 0:
            result_lines.append("...")
        result_lines.extend(diff_lines[start:end+1])
    return result_lines

def get_files(folder):
    file_paths = set()
    for root, _, files in os.walk(folder):
        for file in files:
            file_paths.add(os.path.relpath(os.path.join(root, file), folder))
    return file_paths

def read_file(file_path):
    try:
        if not file_path or not os.path.exists(file_path):
            return []
        
        real_path = os.path.realpath(file_path)
        if not (real_path.startswith(os.path.realpath(PRODUCTS_DIR)) or 
                real_path.startswith(os.path.realpath(SAVED_ANALYSES_DIR))):
            return []
        
        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            return []
        
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()
    except Exception as e:
        app.logger.warning(f"Error reading {file_path}: {e}")
        return []

def save_diff(file_path, diff, output_file):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"{file_path}\n")
        f.write("=" * 8 + "\n")
        f.writelines(diff)
        f.write("=" * 9 + "\n\n")

def compare_single_file(file_info):
    file, old_folder, new_folder, ext_filter, manual_keywords = file_info
    
    if not validate_filename(file):
        return None
    
    if ext_filter and not file.endswith(ext_filter):
        return None
    
    old_path = os.path.join(old_folder, file)
    new_path = os.path.join(new_folder, file)
    
    try:
        if not (os.path.exists(old_path) and os.path.exists(new_path)):
            return None
        
        old_code = read_file(old_path)
        new_code = read_file(new_path)
        
        if not old_code or not new_code:
            return None
        
        diff = list(difflib.unified_diff(old_code, new_code, fromfile=old_path, tofile=new_path, lineterm="\n"))
        
        if not diff:
            return None
            
        save_special = False
        if manual_keywords:
            keywords = [validate_input(k.strip(), 50) for k in manual_keywords if k.strip()]
            keywords = [k for k in keywords if k]
            save_special = any(any(k in line for k in keywords) for line in diff)
        else:
            save_special = True
            
        return {'file': file, 'diff': diff, 'save_special': save_special}
    except Exception as e:
        app.logger.warning(f"Error comparing file {file}: {str(e)}")
        return None

def compare_folders(old_folder, new_folder, ext_filter=None, manual_keywords=None):
    if not old_folder or not new_folder:
        return
    
    if not (os.path.exists(old_folder) and os.path.exists(new_folder)):
        return
    
    old_real = os.path.realpath(old_folder)
    new_real = os.path.realpath(new_folder)
    products_real = os.path.realpath(PRODUCTS_DIR)
    
    if not (old_real.startswith(products_real) and new_real.startswith(products_real)):
        return
    
    temp_dir = tempfile.mkdtemp()
    diff_file = os.path.join(temp_dir, "diff.txt")
    special_file = os.path.join(temp_dir, "special.txt")
    
    try:
        open(diff_file, "w").close()
        open(special_file, "w").close()
        
        old_files = get_files(old_folder)
        new_files = get_files(new_folder)
        common_files = old_files & new_files
        
        if len(common_files) > 10000:
            app.logger.warning(f"Too many files to compare: {len(common_files)}")
            return
        
        file_tasks = [(file, old_folder, new_folder, ext_filter, manual_keywords) for file in common_files]
        max_workers = min(32, len(file_tasks))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(compare_single_file, task): task[0] for task in file_tasks}
            
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                if result:
                    with open(diff_file, "a", encoding="utf-8") as f:
                        f.write(f"{result['file']}\n")
                        f.write("=" * 8 + "\n")
                        f.writelines(result['diff'])
                        f.write("=" * 9 + "\n\n")
                    
                    if result['save_special']:
                        with open(special_file, "a", encoding="utf-8") as f:
                            f.write(f"{result['file']}\n")
                            f.write("=" * 8 + "\n")
                            f.writelines(result['diff'])
                            f.write("=" * 9 + "\n\n")
        
        if os.path.exists(diff_file):
            shutil.copy2(diff_file, "diff.txt")
        if os.path.exists(special_file):
            shutil.copy2(special_file, "special.txt")
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def parse_diff_file(diff_path):
    diffs = []
    if not diff_path or not os.path.exists(diff_path):
        return diffs
    
    try:
        if os.path.getsize(diff_path) > 100 * 1024 * 1024:
            app.logger.warning(f"Diff file too large: {diff_path}")
            return diffs
    except OSError:
        return diffs
    
    try:
        with open(diff_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except (IOError, UnicodeDecodeError) as e:
        app.logger.error(f"Error reading diff file {diff_path}: {str(e)}")
        return diffs
    
    i = 0
    while i < len(lines) and len(diffs) < 1000:
        if lines[i].strip() == "":
            i += 1
            continue
        
        filename = lines[i].rstrip("\n")
        
        if not validate_filename(filename):
            i += 1
            continue
        
        i += 1
        if i < len(lines) and lines[i].strip() == "=" * 8:
            i += 1
        
        diff_lines = []
        while i < len(lines) and lines[i].strip() != "=" * 9 and len(diff_lines) < 10000:
            diff_lines.append(lines[i].rstrip("\n"))
            i += 1
        
        if i < len(lines) and lines[i].strip() == "=" * 9:
            i += 1
        
        while i < len(lines) and lines[i].strip() == "":
            i += 1
        
        diffs.append({'filename': filename, 'diff': diff_lines})
    
    return diffs

def analyze_diffs_with_keywords(diffs, manual_keywords):
    results = {}
    
    if manual_keywords:
        keywords = [validate_input(keyword, 50) for keyword in manual_keywords]
        keywords = [k for k in keywords if k]
        manual_keywords = keywords
    
    for diff in diffs:
        if not isinstance(diff, dict) or 'filename' not in diff or 'diff' not in diff:
            continue
        
        filename = diff['filename']
        diff_lines = diff['diff']
        
        if not validate_filename(filename):
            continue
        
        if manual_keywords:
            match_indices = [i for i, line in enumerate(diff_lines) if any(keyword in line for keyword in manual_keywords)]
        else:
            match_indices = list(range(len(diff_lines)))
        
        if match_indices:
            context_lines = extract_context(diff_lines, sorted(set(match_indices)))
            context_lines = [line.rstrip('\n') for line in context_lines if line.strip()]
            
            if len(context_lines) > 1000:
                context_lines = context_lines[:1000]
            
            if filename not in results:
                results[filename] = {'context': context_lines}
    
    return results

def get_github_versions(repo_url):
    try:
        if not validate_url(repo_url):
            return []
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        url = f"{repo_url}/refs?tag_name=&experimental=1"
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        if not isinstance(data, dict):
            return []
        
        versions = []
        if 'refs' in data and isinstance(data['refs'], list):
            for version in data['refs']:
                if isinstance(version, str):
                    version = version.strip()
                    if validate_version(version):
                        versions.append(version)
        
        versions = list(dict.fromkeys(versions))
        
        if len(versions) > 1000:
            versions = versions[:1000]
        
        def sort_key(version):
            clean_version = version.lstrip('v')
            semantic_match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?', clean_version)
            if semantic_match:
                major, minor, patch, suffix = semantic_match.groups()
                major, minor, patch = int(major), int(minor), int(patch)
                suffix_priority = 0 if suffix is None else 1
                return (0, -major, -minor, -patch, suffix_priority, suffix or "")
            else:
                return (1, version)
        
        versions.sort(key=sort_key)
        if versions and all(sort_key(v)[0] == 1 for v in versions):
            versions.reverse()
        return versions

    except Exception as e:
        app.logger.error(f"Version fetch error: {str(e)}")
        return []

def count_vulnerabilities(results):
    total_count = 0
    for filename, result in results.items():
        if 'vulnerability_status' in result and result['vulnerability_status'].startswith('AI:'):
            vuln_text = result['vulnerability_status'].split('AI: ')[1]
            if not (vuln_text.startswith('Not sure') or vuln_text.startswith('No vulnerabilities')):
                try:
                    vuln_number = int(vuln_text.split(' ')[0])
                    total_count += vuln_number
                except (ValueError, IndexError):
                    pass
    return total_count

def process_ai_analysis(analyzed_results, diffs, cve_ids):
    ai_tasks = [(diff['filename'], '\n'.join(diff['diff'])) for diff in diffs if diff['filename'] in analyzed_results]

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(get_ai_analysis, task[0], task[1]): task[0] for task in ai_tasks}
        
        for future in concurrent.futures.as_completed(futures):
            filename = futures[future]
            try:
                ai_response = future.result()
                analyzed_results[filename]['ai_response'] = ai_response
                
                if cve_ids:
                    cve_results = {}
                    for cve_id in cve_ids.split(','):
                        cve_id = cve_id.strip()
                        if cve_id:
                            cve_description = get_cve_description(cve_id)
                            cve_analysis = analyze_with_cve(ai_response, cve_description)
                            match = re.search(r'Description Matches:\s*(Yes|No)', cve_analysis, re.I)
                            cve_results[cve_id] = {
                                'result': match.group(1).capitalize() if match else 'Unknown',
                                'description': cve_description
                            }
                    analyzed_results[filename]['cve_matches'] = cve_results

                vuln_matches = re.findall(r'(?i)(Vulnerability\s+Existed|Vuln\s+Existence).*?:\s*.*?\b(not[\s\-_]?sure|yes|no)\b', ai_response)
                yes_count = sum(1 for match in vuln_matches if match[1].lower() == 'yes')
                not_sure = any('not sure' in match[1].lower() for match in vuln_matches)
                analyzed_results[filename]['vulnerability_status'] = f"AI: {yes_count} vulnerabilities" if yes_count > 0 else "AI: Not sure" if not_sure else "AI: No vulnerabilities"
                analyzed_results[filename]['vuln_severity'] = 'yes' if yes_count > 0 else 'not sure' if not_sure else 'no'
            except Exception as e:
                analyzed_results[filename]['ai_response'] = f"AI analysis failed: {str(e)}"
                analyzed_results[filename]['vulnerability_status'] = "Analysis error"
                analyzed_results[filename]['vuln_severity'] = 'no'
    
    return analyzed_results

@app.route('/save-analysis', methods=['POST'])
@limiter.limit("10 per minute")
def save_analysis():
    try:
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid JSON data'}), 400
    except Exception:
        return jsonify({'error': 'Invalid JSON data'}), 400
    
    analysis_id = str(uuid.uuid4())
    
    analysis_data = {
        'meta': {
            'created_at': datetime.now().isoformat(),
            'source': validate_input(data.get('source', 'direct'), 20),
            'ai_enabled': bool(data.get('enable_ai', False)),
            'params': data.get('params', {})
        },
        'results': data.get('results', {})
    }
    
    try:
        analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
        with open(analysis_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        os.chmod(analysis_path, 0o644)
        
        return jsonify({'id': analysis_id})
    except Exception as e:
        app.logger.error(f"Error saving analysis: {str(e)}")
        return jsonify({'error': 'Failed to save analysis'}), 500

@app.route('/analysis/<analysis_id>')
@limiter.limit("30 per minute")
def view_analysis(analysis_id):
    if not validate_uuid(analysis_id):
        abort(404)
    
    try:
        analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
        
        if not os.path.exists(analysis_path):
            abort(404)
        
        real_path = os.path.realpath(analysis_path)
        if not real_path.startswith(os.path.realpath(SAVED_ANALYSES_DIR)):
            abort(404)
        
        with open(analysis_path) as f:
            analysis = json.load(f)
        
        if not isinstance(analysis, dict) or 'meta' not in analysis:
            abort(404)
        
        status = analysis['meta'].get('status', 'completed')
        return render_template("analysis.html", analysis=analysis, is_shared=True, analysis_id=analysis_id, status=status)
    except Exception as e:
        app.logger.error(f"Error loading analysis {analysis_id}: {str(e)}")
        return render_template("error.html", message="Analysis not found"), 404

@app.route('/delete-analysis/<analysis_id>', methods=['POST'])
@limiter.limit("10 per minute")
def delete_analysis(analysis_id):
    if not validate_uuid(analysis_id):
        flash('Invalid analysis ID.', 'danger')
        return redirect(url_for('reports'))
    
    try:
        analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
        
        real_path = os.path.realpath(analysis_path)
        if not real_path.startswith(os.path.realpath(SAVED_ANALYSES_DIR)):
            flash('Invalid analysis path.', 'danger')
            return redirect(url_for('reports'))
        
        if os.path.exists(analysis_path):
            os.remove(analysis_path)
            flash('Analysis deleted successfully.', 'success')
            app.logger.info(f"Analysis {analysis_id} deleted")
        else:
            flash('Analysis not found.', 'danger')
    except Exception as e:
        app.logger.error(f"Error deleting analysis {analysis_id}: {str(e)}")
        flash('Error deleting analysis.', 'danger')
    return redirect(url_for('reports'))

@app.route('/ai-settings', methods=['GET','POST'])
@limiter.limit("5 per minute")
def ai_settings():
    if request.method == 'POST':
        ai_service = validate_input(request.form.get('ai_service'), 50)
        ai_service = ai_service if ai_service in VALID_AI_SERVICES else 'ollama'
        
        try:
            temperature = float(request.form.get('temperature', 1.0))
            temperature = max(0, min(2.0, temperature))
        except ValueError:
            temperature = 1.0
        
        try:
            num_ctx = int(request.form.get('num_ctx', 8192))
            num_ctx = max(1024, min(32768, num_ctx))
        except ValueError:
            num_ctx = 8192
        
        config = {
            'service': ai_service,
            'ollama': {
                'url': validate_input(request.form.get('ollama_url'), 200),
                'model': validate_input(request.form.get('ollama_model'), 100)
            },
            'openai': {
                'key': validate_input(request.form.get('openai_key'), 200),
                'model': validate_input(request.form.get('openai_model'), 100),
                'base_url': validate_input(request.form.get('openai_url'), 200)
            },
            'deepseek': {
                'key': validate_input(request.form.get('deepseek_key'), 200),
                'model': validate_input(request.form.get('deepseek_model'), 100),
                'base_url': validate_input(request.form.get('deepseek_url'), 200)
            },
            'claude': {
                'key': validate_input(request.form.get('claude_key'), 200),
                'model': validate_input(request.form.get('claude_model'), 100),
                'base_url': validate_input(request.form.get('claude_url'), 200)
            },
            'parameters': {
                'temperature': temperature,
                'num_ctx': num_ctx
            }
        }
        
        if save_json_safe(AI_CONFIG_FILE, config):
            flash('AI settings updated successfully', 'success')
        else:
            flash('Error saving AI settings', 'danger')
        
        return redirect(url_for('ai_settings'))
    
    return render_template("ai_settings.html", config=load_ai_config())

@app.route('/reports')
@limiter.limit("20 per minute")
def reports():
    saved_analyses = []
    
    try:
        for filename in os.listdir(SAVED_ANALYSES_DIR):
            if filename.endswith('.json'):
                try:
                    analysis_id = filename.replace('.json', '')
                    if not validate_uuid(analysis_id):
                        continue
                    
                    analysis_path = os.path.join(SAVED_ANALYSES_DIR, filename)
                    
                    real_path = os.path.realpath(analysis_path)
                    if not real_path.startswith(os.path.realpath(SAVED_ANALYSES_DIR)):
                        continue
                    
                    with open(analysis_path, 'r') as f:
                        analysis = json.load(f)
                    
                    if not isinstance(analysis, dict) or 'meta' not in analysis:
                        continue
                    
                    analysis['id'] = analysis_id
                    analysis['vuln_count'] = count_vulnerabilities(analysis.get('results', {}))
                    analysis['status'] = analysis['meta'].get('status', 'running')
                    saved_analyses.append(analysis)
                except Exception as e:
                    app.logger.warning(f"Error loading analysis {filename}: {str(e)}")
        
        saved_analyses.sort(key=lambda x: x['meta'].get('created_at', ''), reverse=True)
    except Exception as e:
        app.logger.error(f"Error loading reports: {str(e)}")
    
    return render_template('reports.html', reports=saved_analyses)

@app.route('/manage-products', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def manage_products():
    if request.method == 'POST':
        product_name = validate_input(request.form.get('product_name'), 100, r'^[a-zA-Z0-9._-]+$')
        repo_url = validate_input(request.form.get('repo_url'), 200)
        
        if not product_name or not repo_url:
            return render_template("manage_products.html", error="Both fields are required")
        
        if not validate_url(repo_url):
            return render_template("manage_products.html", error="Invalid repository URL")
        
        products = load_json_safe(PRODUCTS_FILE, {})
        
        if product_name in products:
            return render_template("manage_products.html", error="Product already exists")
        
        products[product_name] = {'repo_url': repo_url, 'versions': []}
        
        if save_json_safe(PRODUCTS_FILE, products):
            flash('Product added successfully', 'success')
        else:
            return render_template("manage_products.html", error="Failed to save product")
        
        return redirect(url_for('manage_products'))

    products = load_json_safe(PRODUCTS_FILE, {})
    return render_template("manage_products.html", products=products)

@app.route('/delete-product/<product_name>')
@limiter.limit("10 per minute")
def delete_product(product_name):
    product_name = validate_input(product_name, 100, r'^[a-zA-Z0-9._-]+$')
    if not product_name:
        flash('Invalid product name', 'danger')
        return redirect(url_for('manage_products'))
    
    products = load_json_safe(PRODUCTS_FILE, {})
    
    if product_name in products:
        del products[product_name]
        
        if save_json_safe(PRODUCTS_FILE, products):
            flash('Product deleted successfully', 'success')
            app.logger.info(f"Product {product_name} deleted")
        else:
            flash('Error deleting product', 'danger')
    else:
        flash('Product not found', 'danger')
    
    return redirect(url_for('manage_products'))

@app.route('/get_versions/<product>')
@limiter.limit("20 per minute")
def get_versions(product):
    product = validate_input(product, 100, r'^[a-zA-Z0-9._-]+$')
    if not product:
        return jsonify([])
    
    try:
        products = load_json_safe(PRODUCTS_FILE, {})
        
        if product in products:
            repo_url = products[product].get('repo_url')
            if validate_url(repo_url):
                return jsonify(get_github_versions(repo_url))
        
        return jsonify([])
    except Exception as e:
        app.logger.error(f"Error getting versions for product {product}: {str(e)}")
        return jsonify([])

def run_analysis_background(analysis_id, params, mode):
    try:
        analysis_path = os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")
        analyzed_results = {}
        
        if mode == 'products':
            product = params['product']
            old_ver = params['old_version']
            new_ver = params['new_version']
            ext_filter = params['extension']
            enable_ai = params['enable_ai']
            special_keywords = params['special_keywords']
            cve_ids = params['cve_ids']
            
            product_versions_file = os.path.join(PRODUCTS_DIR, f"{product}.json")
            versions = load_json_safe(product_versions_file, [])
            
            products_data = load_json_safe(PRODUCTS_FILE, {})
            repo_url = products_data[product]['repo_url']
            
            for ver in [old_ver, new_ver]:
                if not any(v['version'] == ver for v in versions):
                    try:
                        download_dir = os.path.join(PRODUCTS_DIR, f"{product}_downloads")
                        os.makedirs(download_dir, exist_ok=True)
                        zip_url = f"{repo_url}/archive/refs/tags/{ver}.zip"
                        response = requests.get(zip_url, stream=True)
                        zip_path = os.path.join(download_dir, f"{ver}.zip")
                        extract_path = os.path.join(download_dir, ver)
                        
                        with open(zip_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        
                        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                            zip_ref.extractall(extract_path)
                        
                        os.remove(zip_path)
                        final_path = os.path.join(extract_path, os.listdir(extract_path)[0])
                        
                        versions.append({
                            'version': ver,
                            'path': final_path,
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception as e:
                        pass
            
            save_json_safe(product_versions_file, versions)
            
            old_path = next(v['path'] for v in versions if v['version'] == old_ver)
            new_path = next(v['path'] for v in versions if v['version'] == new_ver)
            
            compare_folders(old_path, new_path, ext_filter, special_keywords.split(',') if special_keywords else None)
            diffs = parse_diff_file("special.txt")
            analyzed_results = analyze_diffs_with_keywords(diffs, special_keywords.split(',') if special_keywords else None)
            
            if enable_ai == 'on' and analyzed_results:
                analyzed_results = process_ai_analysis(analyzed_results, diffs, cve_ids)
                
        elif mode == 'folder':
            old_folder = params['old_folder']
            new_folder = params['new_folder']
            ext_filter = params['extension']
            enable_ai = params['enable_ai']
            special_keywords = params['special_keywords']
            cve_ids = params['cve_ids']
            
            compare_folders(old_folder, new_folder, ext_filter, special_keywords.split(',') if special_keywords else None)
            diffs = parse_diff_file("special.txt")
            analyzed_results = analyze_diffs_with_keywords(diffs, special_keywords.split(',') if special_keywords else None)
            
            if enable_ai == 'on' and analyzed_results:
                analyzed_results = process_ai_analysis(analyzed_results, diffs, cve_ids)
        
        with open(analysis_path, 'r') as f:
            analysis_data = json.load(f)
        analysis_data['meta']['status'] = 'completed'
        analysis_data['results'] = analyzed_results
        with open(analysis_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
            
    except Exception as e:
        try:
            with open(analysis_path, 'r') as f:
                analysis_data = json.load(f)
            analysis_data['meta']['status'] = 'failed'
            analysis_data['meta']['error'] = str(e)
            with open(analysis_path, 'w') as f:
                json.dump(analysis_data, f, indent=2)
        except:
            pass

@app.route('/products', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def products():
    products_data = load_json_safe(PRODUCTS_FILE, {})
    products_list = list(products_data.keys()) if isinstance(products_data, dict) else []
    
    if request.method == 'POST':
        product = validate_input(request.form.get('product'), 100)
        old_ver = validate_input(request.form.get('old_version'), 50)
        new_ver = validate_input(request.form.get('new_version'), 50)
        ext_filter = validate_input(request.form.get('extension'), 10)
        enable_ai = request.form.get('enable_ai')
        special_keywords = validate_input(request.form.get('special_keywords'), 500)
        cve_ids = validate_input(request.form.get('cve_ids'), 200)

        if not product or not old_ver or not new_ver:
            flash('Missing required fields', 'error')
            return redirect(url_for('products'))
        
        if product not in products_list:
            flash('Invalid product selected', 'error')
            return redirect(url_for('products'))
        
        if not validate_version(old_ver) or not validate_version(new_ver):
            flash('Invalid version format', 'error')
            return redirect(url_for('products'))

        params = {
            'product': product,
            'old_version': old_ver,
            'new_version': new_ver,
            'extension': ext_filter,
            'enable_ai': enable_ai,
            'special_keywords': special_keywords,
            'cve_ids': cve_ids
        }
        analysis_id = create_new_analysis_record(params, source='products', ai_enabled=(enable_ai == 'on'))
        
        threading.Thread(target=run_analysis_background, args=(analysis_id, params, 'products')).start()
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

    return render_template("products.html", products=products_list, analyzed_results={}, product='', old_version='', new_version='', extension='', enable_ai='', special_keywords='', cve_ids='')

@app.route('/folder', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def folder():
    if request.method == 'POST':
        old_folder = validate_input(request.form.get('old_folder'), 500)
        new_folder = validate_input(request.form.get('new_folder'), 500)
        ext_filter = validate_input(request.form.get('extension'), 10)
        enable_ai = request.form.get('enable_ai')
        special_keywords = validate_input(request.form.get('special_keywords'), 500)
        cve_ids = validate_input(request.form.get('cve_ids'), 200)

        if not old_folder or not new_folder:
            flash('Both folder paths are required', 'error')
            return redirect(url_for('folder'))
        
        if not (os.path.exists(old_folder) and os.path.exists(new_folder)):
            flash('One or both folder paths do not exist', 'error')
            return redirect(url_for('folder'))
        
        try:
            old_real = os.path.realpath(old_folder)
            new_real = os.path.realpath(new_folder)
            products_real = os.path.realpath(PRODUCTS_DIR)
            
            if not (old_real.startswith(products_real) and new_real.startswith(products_real)):
                flash('Folder paths must be within the products directory', 'error')
                return redirect(url_for('folder'))
        except Exception:
            flash('Invalid folder paths', 'error')
            return redirect(url_for('folder'))

        params = {
            'old_folder': old_folder,
            'new_folder': new_folder,
            'extension': ext_filter,
            'enable_ai': enable_ai,
            'special_keywords': special_keywords,
            'cve_ids': cve_ids
        }
        analysis_id = create_new_analysis_record(params, source='folder', ai_enabled=(enable_ai == 'on'))
        
        threading.Thread(target=run_analysis_background, args=(analysis_id, params, 'folder')).start()
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

    return render_template("folder.html", analyzed_results={}, old_folder='', new_folder='', extension='', enable_ai='', special_keywords='', cve_ids='')

@app.route('/library', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def library():
    if request.method == 'POST':
        name = validate_input(request.form.get('name'), 100)
        repo_url = validate_input(request.form.get('repo_url'), 200)
        ai_service = validate_input(request.form.get('ai_service'), 50)
        
        if not name or not repo_url:
            flash('Name and repository URL are required', 'danger')
            return redirect(url_for('library'))
        
        success, message = add_library_repo(name, repo_url, ai_service)
        flash(message, 'success' if success else 'danger')
        return redirect(url_for('library'))
    
    return render_template("library.html", library_repos=load_library())

@app.route('/library/delete/<repo_id>', methods=['POST'])
@limiter.limit("10 per minute")
def delete_library_repo(repo_id):
    if not validate_uuid(repo_id):
        flash('Invalid repository ID', 'danger')
        return redirect(url_for('library'))
    
    if remove_library_repo(repo_id):
        flash('Repository removed from library', 'success')
        app.logger.info(f"Library repo {repo_id} deleted")
    else:
        flash('Repository not found', 'danger')
    
    return redirect(url_for('library'))

@app.route('/library/toggle/<repo_id>', methods=['POST'])
@limiter.limit("10 per minute")
def toggle_library_repo(repo_id):
    if not validate_uuid(repo_id):
        flash('Invalid repository ID', 'danger')
        return redirect(url_for('library'))
    
    library = load_library()
    repo_found = False
    for repo in library:
        if repo.get('id') == repo_id:
            repo['auto_scan'] = not repo.get('auto_scan', True)
            repo_found = True
            break
    
    if repo_found:
        save_library(library)
        flash('Auto-scan setting updated', 'success')
    else:
        flash('Repository not found', 'danger')
    
    return redirect(url_for('library'))

@app.route('/library/check-now', methods=['POST'])
@limiter.limit("3 per minute")
def check_versions_now():
    threading.Thread(target=check_for_new_versions).start()
    flash('Version check started in background', 'info')
    return redirect(url_for('library'))

@app.route('/', methods=['GET'])
@limiter.limit("50 per minute")
def index():
    return render_template("index.html")

if __name__ == '__main__':
    os.makedirs(PRODUCTS_DIR, exist_ok=True)
    os.chmod(PRODUCTS_DIR, 0o755)
    
    if not os.path.exists(os.path.join(PRODUCTS_DIR, 'magento.json')):
        with open(os.path.join(PRODUCTS_DIR, 'magento.json'), 'w') as f:
            json.dump([], f)
    
    app.run(host="127.0.0.1", port=5000, debug=False)
