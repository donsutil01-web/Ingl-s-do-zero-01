import os,sqlite3,json,secrets,time,re
from datetime import timedelta
from flask import Flask,request,session,jsonify,send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
app=Flask(__name__,static_folder='public')
app.config.update(SECRET_KEY=os.environ['SECRET_KEY'],SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SECURE=os.environ.get('APP_ENV')!='test',SESSION_COOKIE_SAMESITE='Lax',PERMANENT_SESSION_LIFETIME=timedelta(days=7),MAX_CONTENT_LENGTH=2*1024*1024)
DB=os.environ.get('DATABASE_PATH','/var/data/ingles.sqlite3')
def db():
 c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row;return c
os.makedirs(os.path.dirname(os.path.abspath(DB)),exist_ok=True)
with db() as c:
 c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL);CREATE TABLE IF NOT EXISTS progress(user_id INTEGER PRIMARY KEY,data TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until INTEGER NOT NULL);')
@app.before_request
def protect():
 if request.path.startswith('/api/') and request.method!='GET':
  if request.headers.get('X-Study-App')!='1':return jsonify(error='Requisição inválida.'),403
  if request.headers.get('Sec-Fetch-Site')=='cross-site':return jsonify(error='Origem inválida.'),403
@app.after_request
def headers(r):
 r.headers['Cache-Control']='no-store';r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';return r
@app.get('/')
def index():return send_from_directory('public','index.html')
@app.get('/health')
def health():return {'ok':True}
@app.get('/api/me')
def me():return {'username':session.get('username')}
@app.post('/api/<action>')
def auth(action):
 if action=='logout':session.clear();return {'ok':True}
 if action not in ('login','register'):return {},404
 body=request.get_json(silent=True) or {};u=body.get('username','');p=body.get('password','')
 if not isinstance(u,str) or not isinstance(p,str):return {'error':'Dados inválidos.'},400
 u=u.strip().lower()
 if not re.fullmatch('[a-z0-9_.-]{3,40}',u) or not 10<=len(p)<=200:return {'error':'Usuário: 3–40 letras sem acento, números, ponto, hífen ou sublinhado. Senha: 10–200 caracteres.'},400
 key=u;now=int(time.time())
 with db() as c:
  a=c.execute('SELECT * FROM attempts WHERE key=?',(key,)).fetchone()
  if a and a['until']>now and a['count']>=10:return {'error':'Muitas tentativas. Aguarde 15 minutos.'},429
  c.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN until<? THEN 1 ELSE count+1 END,until=CASE WHEN until<? THEN excluded.until ELSE until END',(key,now+900,now,now))
 if action=='register':
  try:
   with db() as c:c.execute('INSERT INTO users(username,password) VALUES(?,?)',(u,generate_password_hash(p)))
  except sqlite3.IntegrityError:return {'error':'Nome indisponível. Escolha outro ou entre na sua conta.'},409
 with db() as c:r=c.execute('SELECT * FROM users WHERE username=?',(u,)).fetchone()
 if not r or not check_password_hash(r['password'],p):return {'error':'Usuário ou senha incorretos.'},401
 session.clear();session.update(uid=r['id'],username=u);session.permanent=True
 with db() as c:c.execute('DELETE FROM attempts WHERE key=?',(key,))
 return {'username':u}
@app.route('/api/progress',methods=['GET','PUT'])
def progress():
 uid=session.get('uid')
 if not uid:return {'error':'Entre novamente.'},401
 with db() as c:
  if request.method=='GET':
   r=c.execute('SELECT * FROM progress WHERE user_id=?',(uid,)).fetchone();return {'data':json.loads(r['data']) if r else {'records':{},'log':[]},'version':r['version'] if r else 0}
  b=request.get_json(silent=True) or {};data=b.get('data');version=b.get('version')
  if not isinstance(data,dict) or not isinstance(data.get('records'),dict) or not isinstance(data.get('log'),list) or type(version)!=int:return {'error':'Progresso inválido.'},400
  c.execute('INSERT OR IGNORE INTO progress VALUES(?,?,0)',(uid,json.dumps({'records':{},'log':[]})))
  r=c.execute('UPDATE progress SET data=?,version=version+1 WHERE user_id=? AND version=?',(json.dumps(data),uid,version))
  if r.rowcount!=1:return {'error':'Seu progresso mudou em outro aparelho. Recarregue a página antes de continuar.'},409
 return {'version':version+1}
