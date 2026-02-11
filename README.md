# sniffer_esp

Локальный релиз без GitHub Actions.

## 1. Один раз: подготовка

```powershell
cd C:\esp_projects\sniffer_esp
git pull
```

Создай GitHub PAT (Fine-grained) для репозитория `Samat1989/sniffer_esp` с правами:
- `Contents: Read and write`
- `Metadata: Read`

## 2. Выпуск новой версии (рекомендуемый способ)

Пример для версии `v1.0.4`:

```powershell
cd C:\esp_projects\sniffer_esp
$env:GITHUB_TOKEN="YOUR_NEW_TOKEN"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\release-local.ps1 -Tag v1.0.4 -Push -PublishRelease
```

Что делает команда:
- собирает прошивку локально (`idf.py build`);
- кладет артефакты в `firmware\v1.0.4` и `firmware\latest`;
- коммитит артефакты;
- создает и пушит тег;
- создает/обновляет GitHub Release и загружает `.bin`.

## 3. Публикация уже собранного тега (без пересборки)

```powershell
cd C:\esp_projects\sniffer_esp
$env:GITHUB_TOKEN="YOUR_NEW_TOKEN"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\publish-github-release.ps1 -Tag v1.0.4 -Repo Samat1989/sniffer_esp
```

## 4. Частые ошибки

- `Working tree is not clean`  
  Сначала закоммить или stash изменения:
  ```powershell
  git status --short
  ```

- `GITHUB_TOKEN is empty`  
  Задай токен:
  ```powershell
  $env:GITHUB_TOKEN="YOUR_NEW_TOKEN"
  ```

- `Resource not accessible by personal access token (403)`  
  У токена не хватает прав или выбран не тот репозиторий.

## 5. Проверка результата

- Releases: `https://github.com/Samat1989/sniffer_esp/releases`
- OTA URL:  
  `https://github.com/Samat1989/sniffer_esp/releases/latest/download/sniffer_esp.bin`
