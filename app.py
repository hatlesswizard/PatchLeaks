from flask import Flask, render_template, request, redirect, url_for, jsonify
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

app = Flask(__name__)
ai_cache = TTLCache(maxsize=1000000000, ttl=0)
PRODUCTS_DIR = os.path.join(os.path.dirname(__file__), 'products')
AI_CONFIG_FILE = 'ai_config.json'
PRODUCTS_FILE = os.path.join(PRODUCTS_DIR, 'products.json')
VERSION_CACHE = TTLCache(maxsize=100, ttl=0)
version_lock = Lock()
SAVED_ANALYSES_DIR = os.path.join(os.path.dirname(__file__), 'saved_analyses')
os.makedirs(SAVED_ANALYSES_DIR, exist_ok=True)

def load_ai_config():
    default = {
        'service': 'ollama',
        'ollama': {'url': 'http://localhost:11434', 'model': 'qwen2.5-coder:3b'},
        'openai': {'key': '', 'model': 'gpt-4-turbo', 'base_url': 'https://api.openai.com/v1'},
        'deepseek': {'key': '', 'model': 'deepseek-coder-33b-instruct', 'base_url': 'https://api.deepseek.com/v1'},
        'claude': {'key': '', 'model': 'claude-3-opus-20240229', 'base_url': 'https://api.anthropic.com/v1'},
        'parameters': {'temperature': 1.0, 'num_ctx': 8192}
    }
    try:
        with open(AI_CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Merge with defaults to ensure all fields exist
            for service in ['openai', 'deepseek', 'claude']:
                if service not in config:
                    config[service] = default[service]
                else:
                    # Preserve existing values, only add missing ones
                    for key, value in default[service].items():
                        if key not in config[service] or config[service][key] is None:
                            config[service][key] = value
            return config
    except:
        return default

@cached(ai_cache)
def get_ai_analysis(file_path, diff_content):
    config = load_ai_config()
    prompt = f"Analyze the provided code diff for security fixes.\n\nInstructions:\n1. Your answer MUST strictly follow the answer format outlined below.\n2. Always include the vulnerability name if one exists.\n3. There may be multiple vulnerabilities. For each, provide a separate entry following the structure.\n4. Even if you are uncertain whether a vulnerability exists, follow the structure and indicate your uncertainty.\n\nAnswer Format for Each Vulnerability:\n    Vulnerability Existed: [yes/no/not sure]\n    [Vulnerability Name] [File] [Lines]\n    [Old Code]\n    [Fixed Code]\n\nAdditional Details:\n    File: {file_path}\n    Diff Content:\n    {diff_content}"
    
    retry_count = 0
    while True:
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
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json().get('response', 'No AI response') if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'openai':
                headers = {'Authorization': f"Bearer {config['openai']['key']}"}
                response = requests.post(
                    f"{config['openai']['base_url']}/chat/completions",
                    headers=headers,
                    json={
                        'model': config['openai']['model'],
                        'messages': [{'role': 'user', 'content': prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'deepseek':
                headers = {'Authorization': f"Bearer {config['deepseek']['key']}"}
                response = requests.post(
                    f"{config['deepseek']['base_url']}/chat/completions",
                    headers=headers,
                    json={
                        'model': config['deepseek']['model'],
                        'messages': [{'role': 'user', 'content': prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'claude':
                headers = {'x-api-key': config['claude']['key'], 'anthropic-version': '2023-06-01'}
                response = requests.post(
                    f"{config['claude']['base_url']}/messages",
                    headers=headers,
                    json={
                        'model': config['claude']['model'],
                        'max_tokens': config['parameters']['num_ctx'],
                        'temperature': config['parameters']['temperature'],
                        'messages': [{'role': 'user', 'content': prompt}]
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['content'][0]['text'] if response.ok else f"Error: {response.text}"
                
            return "Invalid AI service configuration"
            
        except Exception as e:
            if hasattr(e, 'response') and getattr(e.response, 'status_code', None) == 429:
                retry_count += 1
                print(f"Rate limit exceeded (429). Retrying... (attempt {retry_count})")
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
    while True:
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
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying CVE analysis... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json().get('response', 'No AI response') if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'openai':
                headers = {'Authorization': f"Bearer {config['openai']['key']}"}
                response = requests.post(
                    f"{config['openai']['base_url']}/chat/completions",
                    headers=headers,
                    json={
                        'model': config['openai']['model'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying CVE analysis... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'deepseek':
                headers = {'Authorization': f"Bearer {config['deepseek']['key']}"}
                response = requests.post(
                    f"{config['deepseek']['base_url']}/chat/completions",
                    headers=headers,
                    json={
                        'model': config['deepseek']['model'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}],
                        'temperature': config['parameters']['temperature'],
                        'max_tokens': config['parameters']['num_ctx']
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying CVE analysis... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['choices'][0]['message']['content'] if response.ok else f"Error: {response.text}"
                
            elif config['service'] == 'claude':
                headers = {'x-api-key': config['claude']['key'], 'anthropic-version': '2023-06-01'}
                response = requests.post(
                    f"{config['claude']['base_url']}/messages",
                    headers=headers,
                    json={
                        'model': config['claude']['model'],
                        'max_tokens': config['parameters']['num_ctx'],
                        'temperature': config['parameters']['temperature'],
                        'messages': [{'role': 'user', 'content': analysis_prompt}]
                    },
                    timeout=999999
                )
                
                if response.status_code == 429:
                    retry_count += 1
                    print(f"Rate limit exceeded (429). Retrying CVE analysis... (attempt {retry_count})")
                    time.sleep(min(2 ** retry_count, 60))
                    continue
                    
                return response.json()['content'][0]['text'] if response.ok else f"Error: {response.text}"
                
            return "CVE analysis failed: Unsupported AI service"
            
        except Exception as e:
            if hasattr(e, 'response') and getattr(e.response, 'status_code', None) == 429:
                retry_count += 1
                print(f"Rate limit exceeded (429). Retrying CVE analysis... (attempt {retry_count})")
                time.sleep(min(2 ** retry_count, 60))
                continue
            return f"CVE analysis error: {str(e)}"


def extract_context(diff_lines, match_indices, context=15):
    intervals = []
    for idx in match_indices:
        start = max(0, idx - context)
        end = min(len(diff_lines) - 1, idx + context)
        intervals.append((start, end))
    intervals.sort(key=lambda x: x[0])
    merged = []
    for interval in intervals:
        if not merged:
            merged.append(list(interval))
        else:
            last = merged[-1]
            if interval[0] <= last[1] + 1:
                last[1] = max(last[1], interval[1])
            else:
                merged.append(list(interval))
    result_lines = []
    for i, (start, end) in enumerate(merged):
        if i > 0:
            result_lines.append("...")
        result_lines.extend(diff_lines[start:end+1])
    return result_lines

def get_files(folder):
    file_paths = []
    for root, _, files in os.walk(folder):
        for file in files:
            file_paths.append(os.path.relpath(os.path.join(root, file), folder))
    return set(file_paths)

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def save_diff(file_path, diff, output_file):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"{file_path}\n")
        f.write("=" * 8 + "\n")
        f.writelines(diff)
        f.write("=" * 9 + "\n\n")

def compare_single_file(file_info):
    """Compare a single file between old and new folders"""
    file, old_folder, new_folder, ext_filter, manual_keywords = file_info
    
    if ext_filter and not file.endswith(ext_filter):
        return None
    
    old_path = os.path.join(old_folder, file)
    new_path = os.path.join(new_folder, file)
    
    try:
        old_code = read_file(old_path)
        new_code = read_file(new_path)
        diff = list(difflib.unified_diff(
            old_code, new_code,
            fromfile=old_path,
            tofile=new_path,
            lineterm="\n"
        ))
        
        if not diff:
            return None
            
        # Check if diff contains keywords
        save_special = False
        if manual_keywords:
            keywords = [k.strip() for k in manual_keywords if k.strip()]
            for line in diff:
                if any(k in line for k in keywords):
                    save_special = True
                    break
        else:
            save_special = True
            
        return {
            'file': file,
            'diff': diff,
            'save_special': save_special
        }
    except Exception as e:
        print(f"Error comparing file {file}: {str(e)}")
        return None

def compare_folders(old_folder, new_folder, ext_filter=None, manual_keywords=None):
    """Multithreaded folder comparison"""
    open("diff.txt", "w").close()
    open("special.txt", "w").close()
    
    old_files = get_files(old_folder)
    new_files = get_files(new_folder)
    common_files = old_files & new_files
    
    # Prepare file comparison tasks
    file_tasks = [
        (file, old_folder, new_folder, ext_filter, manual_keywords)
        for file in common_files
    ]
    
    # Use ThreadPoolExecutor for parallel processing
    max_workers = min(32, len(file_tasks))  # Cap at 32 threads to avoid overwhelming the system
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(compare_single_file, task): task[0]
            for task in file_tasks
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_file):
            result = future.result()
            if result:
                # Thread-safe file writing
                with open("diff.txt", "a", encoding="utf-8") as f:
                    f.write(f"{result['file']}\n")
                    f.write("=" * 8 + "\n")
                    f.writelines(result['diff'])
                    f.write("=" * 9 + "\n\n")
                
                if result['save_special']:
                    with open("special.txt", "a", encoding="utf-8") as f:
                        f.write(f"{result['file']}\n")
                        f.write("=" * 8 + "\n")
                        f.writelines(result['diff'])
                        f.write("=" * 9 + "\n\n")

def parse_diff_file(diff_path):
    diffs = []
    if not os.path.exists(diff_path):
        return diffs
    with open(diff_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() == "":
            i += 1
            continue
        filename = lines[i].rstrip("\n")
        i += 1
        if i < len(lines) and lines[i].strip() == "=" * 8:
            i += 1
        diff_lines = []
        while i < len(lines) and lines[i].strip() != "=" * 9:
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
    for diff in diffs:
        if manual_keywords:
            match_indices = [
                i for i, line in enumerate(diff['diff'])
                if any(keyword in line for keyword in manual_keywords)
            ]
        else:
            match_indices = [i for i, _ in enumerate(diff['diff'])]
        if match_indices:
            context_lines = extract_context(diff['diff'], sorted(list(set(match_indices))))
            context_lines = [line.rstrip('\n') for line in context_lines if line.strip() != '']
            if diff['filename'] not in results:
                results[diff['filename']] = {
                    'context': context_lines
                }
    return results

def get_github_versions(repo_url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': 'text/fragment+html',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        versions = []
        page = 1
        has_more = True
        
        while has_more:
            url = f"{repo_url}/refs?tag_name=2.4.8&experimental=1"
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            version_spans = soup.find_all('span', class_='ActionListItem-label')
            
            if not version_spans:
                break
                
            for span in version_spans:
                version = span.text.strip()
                if re.match(r'^v?\d+\.\d+\.\d+(?:-[a-z0-9]+)?$', version, re.I):
                    versions.append(version)
            
            next_button = soup.find('button', text='Next')
            if not next_button or 'disabled' in next_button.get('class', []):
                has_more = False
            else:
                page += 1

        versions = list(dict.fromkeys(versions))
        versions.sort(key=lambda x: tuple(map(int, re.findall(r'\d+', x.lstrip('v').split('-')[0]))), reverse=True)
        
        return versions

    except Exception as e:
        print(f"Version fetch error: {str(e)}")
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
    ai_tasks = []
    for diff in diffs:
        filename = diff['filename']
        if filename in analyzed_results:
            diff_content = '\n'.join(diff['diff'])
            ai_tasks.append((filename, diff_content))

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(get_ai_analysis, task[0], task[1]): task[0]
            for task in ai_tasks
        }
        
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
def save_analysis():
    data = request.json
    analysis_id = str(uuid.uuid4())
    
    analysis_data = {
        'meta': {
            'created_at': datetime.now().isoformat(),
            'source': data.get('source', 'direct'),
            'ai_enabled': data['enable_ai'],
            'params': data['params']
        },
        'results': data['results']
    }
    
    with open(os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json"), 'w') as f:
        json.dump(analysis_data, f, indent=2)
    
    return jsonify({'id': analysis_id})

@app.route('/analysis/<analysis_id>')
def view_analysis(analysis_id):
    try:
        with open(os.path.join(SAVED_ANALYSES_DIR, f"{analysis_id}.json")) as f:
            analysis = json.load(f)
            
        return render_template(
            "analysis.html",
            analysis=analysis,
            is_shared=True,
            analysis_id=analysis_id
        )
    except:
        return render_template("error.html", message="Analysis not found"), 404

@app.route('/ai-settings', methods=['GET','POST'])
def ai_settings():
    if request.method == 'POST':
        config = {
            'service': request.form.get('ai_service', 'ollama'),
            'ollama': {
                'url': request.form.get('ollama_url'),
                'model': request.form.get('ollama_model')
            },
            'openai': {
                'key': request.form.get('openai_key'),
                'model': request.form.get('openai_model'),
                'base_url': request.form.get('openai_url')
            },
            'deepseek': {
                'key': request.form.get('deepseek_key'),
                'model': request.form.get('deepseek_model'),
                'base_url': request.form.get('deepseek_url')
            },
            'claude': {
                'key': request.form.get('claude_key'),
                'model': request.form.get('claude_model'),
                'base_url': request.form.get('claude_url')
            },
            'parameters': {
                'temperature': float(request.form.get('temperature', 1.0)),
                'num_ctx': int(request.form.get('num_ctx', 8192))
            }
        }
        with open(AI_CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        return redirect(url_for('ai_settings'))
    current_config = load_ai_config()
    return render_template("ai_settings.html", config=current_config)

@app.route('/reports')
def reports():
    saved_analyses = []
    
    for filename in os.listdir(SAVED_ANALYSES_DIR):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(SAVED_ANALYSES_DIR, filename), 'r') as f:
                    analysis = json.load(f)
                    analysis_id = filename.replace('.json', '')
                    analysis['id'] = analysis_id
                    analysis['vuln_count'] = count_vulnerabilities(analysis['results'])
                    saved_analyses.append(analysis)
            except Exception as e:
                print(f"Error loading analysis {filename}: {str(e)}")
    
    saved_analyses.sort(key=lambda x: x['meta']['created_at'], reverse=True)
    
    return render_template('reports.html', reports=saved_analyses)

@app.route('/manage-products', methods=['GET', 'POST'])
def manage_products():
    if request.method == 'POST':
        product_name = request.form.get('product_name').strip().lower()
        repo_url = request.form.get('repo_url').strip()
        
        if not product_name or not repo_url:
            return render_template("manage_products.html", error="Both fields are required")
            
        products = {}
        try:
            with open(PRODUCTS_FILE, 'r') as f:
                products = json.load(f)
        except:
            pass
            
        products[product_name] = {
            'repo_url': repo_url,
            'versions': []
        }
        
        with open(PRODUCTS_FILE, 'w') as f:
            json.dump(products, f, indent=2)
            
        return redirect(url_for('manage_products'))

    try:
        with open(PRODUCTS_FILE, 'r') as f:
            products = json.load(f)
    except:
        products = {}
        
    return render_template("manage_products.html", products=products)

@app.route('/delete-product/<product_name>')
def delete_product(product_name):
    try:
        with open(PRODUCTS_FILE, 'r') as f:
            products = json.load(f)
        
        if product_name in products:
            del products[product_name]
            
            with open(PRODUCTS_FILE, 'w') as f:
                json.dump(products, f, indent=2)
                
    except Exception as e:
        print(f"Error deleting product: {str(e)}")
        
    return redirect(url_for('manage_products'))

@app.route('/get_versions/<product>')
def get_versions(product):
    try:
        with open(PRODUCTS_FILE, 'r') as f:
            products = json.load(f)
            
        if product in products:
            repo_url = products[product]['repo_url']
            return jsonify(get_github_versions(repo_url))
            
        return jsonify([])
            
    except Exception as e:
        return jsonify([])

@app.route('/products', methods=['GET', 'POST'])
def products():
    products_list = []
    try:
        with open(PRODUCTS_FILE, 'r') as f:
            products = json.load(f)
            products_list = list(products.keys())
    except:
        pass
    
    if request.method == 'POST':
        product = request.form.get('product')
        old_ver = request.form.get('old_version')
        new_ver = request.form.get('new_version')
        ext_filter = request.form.get('extension')
        enable_ai = request.form.get('enable_ai')
        special_keywords = request.form.get('special_keywords')
        cve_ids = request.form.get('cve_ids')
        
        try:
            product_versions_file = os.path.join(PRODUCTS_DIR, f"{product}.json")
            
            try:
                with open(product_versions_file, 'r') as f:
                    versions = json.load(f)
            except:
                versions = []

            new_versions_added = False
            download_errors = []

            with open(PRODUCTS_FILE, 'r') as f:
                products_data = json.load(f)
            
            if product not in products_data:
                raise Exception("Product not found")
            
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
                        new_versions_added = True
                    except Exception as e:
                        download_errors.append(f"Failed to download {ver}: {str(e)}")

            if download_errors:
                return render_template("products.html",
                                    products=products_list,
                                    error=" | ".join(download_errors))

            if new_versions_added:
                with open(product_versions_file, 'w') as f:
                    json.dump(versions, f, indent=2)

            old_path = next(v['path'] for v in versions if v['version'] == old_ver)
            new_path = next(v['path'] for v in versions if v['version'] == new_ver)
            
            compare_folders(
                old_folder=old_path,
                new_folder=new_path,
                ext_filter=ext_filter,
                manual_keywords=special_keywords.split(',') if special_keywords else None
            )
            
            diffs = parse_diff_file("special.txt")
            analyzed_results = analyze_diffs_with_keywords(
                diffs=diffs,
                manual_keywords=special_keywords.split(',') if special_keywords else None
            )

            if enable_ai == 'on' and analyzed_results:
                analyzed_results = process_ai_analysis(analyzed_results, diffs, cve_ids)

            return render_template("products.html",
                                products=products_list,
                                analyzed_results=analyzed_results,
                                product=product,
                                old_version=old_ver,
                                new_version=new_ver,
                                extension=ext_filter,
                                enable_ai=enable_ai,
                                special_keywords=special_keywords,
                                cve_ids=cve_ids)

        except Exception as e:
            return render_template("products.html",
                                products=products_list,
                                error=str(e),
                                product=product,
                                old_version=old_ver,
                                new_version=new_ver,
                                extension=ext_filter,
                                enable_ai=enable_ai,
                                special_keywords=special_keywords,
                                cve_ids=cve_ids)

    return render_template("products.html", 
                         products=products_list,
                         analyzed_results={},
                         product='',
                         old_version='',
                         new_version='',
                         extension='',
                         enable_ai='',
                         special_keywords='',
                         cve_ids='')

@app.route('/folder', methods=['GET', 'POST'])
def folder():
    if request.method == 'POST':
        old_folder = request.form.get('old_folder')
        new_folder = request.form.get('new_folder')
        ext_filter = request.form.get('extension')
        enable_ai = request.form.get('enable_ai')
        special_keywords = request.form.get('special_keywords')
        cve_ids = request.form.get('cve_ids')

        if not os.path.isdir(old_folder) or not os.path.isdir(new_folder):
            return render_template("folder.html", error="Invalid directories")

        compare_folders(
            old_folder=old_folder,
            new_folder=new_folder,
            ext_filter=ext_filter,
            manual_keywords=special_keywords.split(',') if special_keywords else None
        )
        
        diffs = parse_diff_file("special.txt")
        analyzed_results = analyze_diffs_with_keywords(
            diffs=diffs,
            manual_keywords=special_keywords.split(',') if special_keywords else None
        )

        if enable_ai == 'on' and analyzed_results:
            analyzed_results = process_ai_analysis(analyzed_results, diffs, cve_ids)

        return render_template("folder.html",
                            analyzed_results=analyzed_results,
                            old_folder=old_folder,
                            new_folder=new_folder,
                            extension=ext_filter,
                            enable_ai=enable_ai,
                            special_keywords=special_keywords,
                            cve_ids=cve_ids)

    return render_template("folder.html",
                        analyzed_results={},
                        old_folder='',
                        new_folder='',
                        extension='',
                        enable_ai='',
                        special_keywords='',
                        cve_ids='')

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")

if __name__ == '__main__':
    os.makedirs(PRODUCTS_DIR, exist_ok=True)
    if not os.path.exists(os.path.join(PRODUCTS_DIR, 'magento.json')):
        with open(os.path.join(PRODUCTS_DIR, 'magento.json'), 'w') as f:
            json.dump([], f)
    app.run(host="0.0.0.0", port=80, debug=True)
