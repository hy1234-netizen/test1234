import express from 'express';
import JSZip from 'jszip';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';

const PORT = Number(process.env.PORT) || 3000;
const MAX_CODE_LENGTH = 20000;
const EXEC_TIMEOUT_MS = 2500;

const SAFE_ROOT_FILES = [
  'package.json',
  'bun.lock',
  '.gitignore',
  'tsconfig.json',
  'vite.config.ts',
  'index.html',
  'metadata.json',
  '.env.example',
  'server.ts',
];

const APP_README_CONTENT = `# 코드공방 — 인터랙티브 Python 3 학습 스튜디오

브라우저에서 직접 **Python 3** 코드를 실행하고, 단계별 개념·미션·선택 심화 학습과 파이썬 기반 웹페이지 생성을 체험할 수 있는 풀스택 교육용 웹 애플리케이션입니다.

## 주요 기능
- **30개 단계별 파이썬 레슨 (6개 트랙)**: 필수 과정 20개 + 선택 심화 10개
- **레슨 내 3단 학습 탭**: \`개념·예시\` / \`실습 미션\` / \`심화 (선택)\`
- **완료 상태 추적**: 미션 자동 완료 판정, 수동 완료 토글, 트랙별·전체 진도율 저장
- **실시간 Python 3 샌드박스**: Express 백엔드에서 \`python3 -I\` + AST 화이트리스트 검증으로 안전한 코드 실행
- **파이썬 웹 빌더 실습**: 파이썬이 생성한 HTML을 실시간 미리보기와 URL 라우터 시뮬레이터로 확인

## 실행 요구 사항
- **Node.js** 18 이상 (\`npm\` 포함)
- **Python 3.10** 이상 (\`python3\` CLI 실행 가능 환경)

## 로컬 실행 방법
\`\`\`bash
# 1. 의존성 설치
npm install

# 2. 개발 서버 실행 (http://localhost:3000)
npm run dev
\`\`\`

## 프로덕션 빌드 및 실행
\`\`\`bash
npm run build
npm start
\`\`\`

## 환경 변수 설정
필요 시 \`.env.example\`을 복사해 \`.env\` 파일을 생성하세요. (기본 학습 및 Python 3 실행 기능은 별도 API 키 없이 동작합니다.)
`;

const APACHE_LICENSE_CONTENT = `Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
`;

const GITHUB_CI_WORKFLOW = `name: Build and Typecheck

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install
      - run: npm run lint
      - run: npm run build
`;

function collectSafeFiles(dirPath: string, rootDir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dirPath)) return out;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (
      entry.name.startsWith('.') ||
      entry.name === 'node_modules' ||
      entry.name === 'dist'
    ) {
      continue;
    }
    const fullPath = path.resolve(dirPath, entry.name);
    if (!fullPath.startsWith(rootDir + path.sep)) {
      continue;
    }
    if (entry.isDirectory()) {
      collectSafeFiles(fullPath, rootDir, out);
    } else if (entry.isFile()) {
      out.push(fullPath);
    }
  }
  return out;
}

/**
 * Python runner harness executed via `python3 -I` (isolated mode).
 * Parses user code with `ast.parse` to allow only safe educational standard library modules
 * and blocks file/system/network access before executing with stdout/stderr capture.
 */
const PYTHON_SANDBOX_HARNESS = `
import ast
import io
import json
import sys
import traceback
from contextlib import redirect_stdout, redirect_stderr

ALLOWED_MODULES = {
    "math",
    "random",
    "statistics",
    "datetime",
    "collections",
    "itertools",
    "functools",
    "json",
    "re",
    "string",
    "decimal",
    "fractions",
    "html",
    "contextlib",
}

BLOCKED_CALLS = {"open", "eval", "exec", "compile", "__import__", "breakpoint", "input"}

class SafetyVisitor(ast.NodeVisitor):
    def visit_Import(self, node):
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root not in ALLOWED_MODULES:
                raise PermissionError(f"보안 정책상 '{alias.name}' 모듈은 실습 환경에서 가져올 수 없습니다.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            root = node.module.split(".")[0]
            if root not in ALLOWED_MODULES:
                raise PermissionError(f"보안 정책상 '{node.module}' 모듈은 실습 환경에서 가져올 수 없습니다.")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
            if node.func.id == "input":
                raise PermissionError("웹 실습 환경에서는 input() 대신 변수에 직접 테스트 값을 대입해 실행해주세요.")
            raise PermissionError(f"보안 정책상 '{node.func.id}()' 함수는 사용할 수 없습니다.")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr.startswith("__") and node.attr.endswith("__"):
            if node.attr not in {"__init__", "__str__", "__repr__", "__len__", "__name__", "__enter__", "__exit__", "__doc__"}:
                raise PermissionError(f"보안 정책상 특수 속성 '{node.attr}' 접근은 제한됩니다.")
        self.generic_visit(node)

def translate_error(exc):
    name = type(exc).__name__
    msg = str(exc)
    if isinstance(exc, IndentationError):
        return f"들여쓰기 오류 (IndentationError, {exc.lineno}번째 줄): 파이썬은 공백 4칸 들여쓰기가 정확해야 합니다. ({msg})"
    if isinstance(exc, SyntaxError):
        return f"문법 오류 (SyntaxError, {exc.lineno}번째 줄): 콜론(:), 괄호, 따옴표가 빠지지 않았는지 확인해보세요. ({msg})"
    if isinstance(exc, NameError):
        return f"이름 오류 (NameError): 정의되지 않은 변수나 함수를 사용했습니다. 오타가 없는지 확인하세요. ({msg})"
    if isinstance(exc, TypeError):
        return f"자료형 오류 (TypeError): 서로 호환되지 않는 자료형끼리 연산했거나 인자 개수가 다릅니다. ({msg})"
    if isinstance(exc, IndexError):
        return f"인덱스 오류 (IndexError): 리스트 범위를 벗어난 위치에 접근했습니다. ({msg})"
    if isinstance(exc, KeyError):
        return f"키 오류 (KeyError): 딕셔너리에 존재하지 않는 키({msg})를 조회했습니다. .get() 사용을 고려해보세요."
    if isinstance(exc, ZeroDivisionError):
        return "나눗셈 오류 (ZeroDivisionError): 0으로 나눌 수 없습니다."
    if isinstance(exc, ValueError):
        return f"값 오류 (ValueError): 함수에 전달된 값의 형식이나 범위가 올바르지 않습니다. ({msg})"
    return f"{name}: {msg}"

def main():
    payload = json.loads(sys.stdin.read())
    code = payload.get("code", "")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    try:
        tree = ast.parse(code, filename="main.py", mode="exec")
        SafetyVisitor().visit(tree)
        compiled = compile(tree, filename="main.py", mode="exec")
        safe_globals = {"__name__": "__main__"}
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            exec(compiled, safe_globals, safe_globals)
        print(json.dumps({
            "success": True,
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
            "error": None
        }, ensure_ascii=False))
    except Exception as exc:
        lineno = getattr(exc, "lineno", None)
        if lineno is None:
            tb = traceback.extract_tb(exc.__traceback__)
            for frame in reversed(tb):
                if frame.filename == "main.py":
                    lineno = frame.lineno
                    break
        prefix = f"[{lineno}번째 줄] " if lineno else ""
        print(json.dumps({
            "success": False,
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
            "error": prefix + translate_error(exc)
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()
`;

function runPythonSandboxed(code: string): Promise<{
  success: boolean;
  stdout: string;
  stderr: string;
  error: string | null;
  durationMs: number;
}> {
  return new Promise((resolve) => {
    const start = performance.now();
    const child = spawn('python3', ['-I', '-c', PYTHON_SANDBOX_HARNESS], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH || '/usr/bin:/bin', PYTHONIOENCODING: 'utf-8' },
    });

    let stdoutData = '';
    let stderrData = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill('SIGKILL');
        resolve({
          success: false,
          stdout: '',
          stderr: '',
          error: '실행 시간 제한(2.5초)을 초과했습니다. 무한 반복문(while 등)이 있는지 확인해보세요.',
          durationMs: EXEC_TIMEOUT_MS,
        });
      }
    }, EXEC_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => {
      if (stdoutData.length < 65536) {
        stdoutData += chunk.toString('utf8');
      }
    });

    child.stderr.on('data', (chunk) => {
      if (stderrData.length < 16384) {
        stderrData += chunk.toString('utf8');
      }
    });

    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({
          success: false,
          stdout: '',
          stderr: '',
          error: `Python 실행기 호출 실패: ${err.message}`,
          durationMs: Math.round(performance.now() - start),
        });
      }
    });

    child.on('close', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const durationMs = Math.max(1, Number((performance.now() - start).toFixed(2)));

      try {
        const parsed = JSON.parse(stdoutData.trim());
        resolve({
          success: Boolean(parsed.success),
          stdout: parsed.stdout || '',
          stderr: parsed.stderr || '',
          error: parsed.error || null,
          durationMs,
        });
      } catch {
        resolve({
          success: false,
          stdout: stdoutData,
          stderr: stderrData,
          error: stderrData.trim() || '코드 실행 결과를 해석하는 중 오류가 발생했습니다.',
          durationMs,
        });
      }
    });

    child.stdin.write(JSON.stringify({ code }));
    child.stdin.end();
  });
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.post('/api/run-python', async (req, res) => {
    const code = req.body?.code;
    if (typeof code !== 'string') {
      res.status(400).json({
        success: false,
        stdout: '',
        stderr: '',
        error: '유효한 Python 코드 문자열이 전달되지 않았습니다.',
        durationMs: 0,
      });
      return;
    }

    if (code.length > MAX_CODE_LENGTH) {
      res.status(400).json({
        success: false,
        stdout: '',
        stderr: '',
        error: '코드 길이가 최대 허용치(20,000자)를 초과했습니다.',
        durationMs: 0,
      });
      return;
    }

    const result = await runPythonSandboxed(code);
    res.json(result);
  });

  const handleDownloadAppZip = async (
    _req: express.Request,
    res: express.Response
  ) => {
    try {
      const rootDir = path.resolve(process.cwd());
      const zip = new JSZip();
      let fileCount = 0;

      for (const relFile of SAFE_ROOT_FILES) {
        const absFile = path.resolve(rootDir, relFile);
        if (absFile.startsWith(rootDir + path.sep) && fs.existsSync(absFile)) {
          zip.file(relFile, fs.readFileSync(absFile));
          fileCount++;
        }
      }

      const srcDir = path.resolve(rootDir, 'src');
      const srcFiles = collectSafeFiles(srcDir, rootDir);
      for (const absFile of srcFiles) {
        const relPath = path.relative(rootDir, absFile).replace(/\\/g, '/');
        zip.file(relPath, fs.readFileSync(absFile));
        fileCount++;
      }

      const readmePath = path.resolve(rootDir, 'README.md');
      if (fs.existsSync(readmePath)) {
        zip.file('README.md', fs.readFileSync(readmePath));
      } else {
        zip.file('README.md', APP_README_CONTENT);
      }
      fileCount++;

      const licensePath = path.resolve(rootDir, 'LICENSE');
      if (fs.existsSync(licensePath)) {
        zip.file('LICENSE', fs.readFileSync(licensePath));
      } else {
        zip.file('LICENSE', APACHE_LICENSE_CONTENT);
      }
      fileCount++;

      const ciPath = path.resolve(rootDir, '.github/workflows/ci.yml');
      if (fs.existsSync(ciPath)) {
        zip.file('.github/workflows/ci.yml', fs.readFileSync(ciPath));
      } else {
        zip.file('.github/workflows/ci.yml', GITHUB_CI_WORKFLOW);
      }
      fileCount++;

      const buffer = await zip.generateAsync({
        type: 'nodebuffer',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 },
      });

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="codecraft-python-studio-github.zip"'
      );
      res.setHeader('Content-Length', String(buffer.length));
      res.setHeader('X-Zip-File-Count', String(fileCount));
      res.send(buffer);
    } catch {
      res.status(500).json({
        success: false,
        error: 'GitHub 업로드용 .zip 파일을 생성하는 중 오류가 발생했습니다.',
      });
    }
  };

  app.get('/api/download-app-zip', handleDownloadAppZip);
  app.get('/api/download-source-zip', handleDownloadAppZip);

  const isProd = process.env.NODE_ENV === 'production';
  const distDir = path.resolve(process.cwd(), 'dist');

  if (!isProd || !fs.existsSync(distDir)) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

startServer();
