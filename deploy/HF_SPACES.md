# Despliegue en Hugging Face Spaces

Este repo ya está preparado como **Docker Space**:
- `README.md` tiene la metadata YAML (`sdk: docker`, `app_port: 7860`).
- `Dockerfile` expone `7860`.
- `ciberbot/healthserver.py` levanta un HTTP en `0.0.0.0:7860` para que HF lo detecte como "Running".
- El bot Telegram corre en paralelo en el mismo proceso.

## Pasos

1. Crea el Space en https://huggingface.co/spaces (o usa el ya existente).
   - **SDK**: Docker.
   - Privado o público, da igual.

2. En el Space → *Settings* → *Variables and secrets* → **New secret**:
   - Name: `TELEGRAM_BOT_TOKEN`
   - Value: tu token de @BotFather
   - (Opcional) `ALLOWED_USER_IDS`, `DEFAULT_LANG`, etc.

3. Sube el código. Una opción rápida desde tu máquina:

   ```bash
   # con git push estándar (recomendado)
   git remote add hf https://huggingface.co/spaces/<usuario>/<space>
   git push hf main
   # te pedirá usuario + token de HF (no la contraseña).
   # genera el token aquí: https://huggingface.co/settings/tokens (write)
   ```

   O usando `huggingface-cli`:

   ```bash
   pip install -U huggingface_hub
   huggingface-cli login            # pega tu token de HF
   huggingface-cli upload-folder \
     --repo-id <usuario>/<space> \
     --repo-type space \
     .
   ```

4. HF construirá la imagen y arrancará el container. En *Logs* deberías ver:
   ```
   Health server escuchando en :7860
   CiberBot iniciado.
   ```

## Notas

- Si el Space queda "sleeping" en plan free, el bot deja de responder. Para 24/7 necesitas plan pago **o** un VPS.
- Las polling de Telegram son salientes, así que no necesitas configurar webhooks ni dominio público.
- Si actualizas reglas YARA, súbelas a `yara_rules/` y haz `git push`; HF reconstruye.
- HF Spaces solo expone **un** puerto público (`app_port`). Las métricas Prometheus en 9090 quedan internas.
