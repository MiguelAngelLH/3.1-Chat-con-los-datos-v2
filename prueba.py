import pandas as pd
from groq import Groq
import streamlit as st
import os
import re
import chardet
import logging

# Configuración inicial
st.set_page_config(page_title="Analizador de CSV con Groq", layout="wide")

# Configuración de logger
logger = logging.getLogger('streamlit')

# Función para cargar el CSV
def load_csv(file):
    try:
        return pd.read_csv(file)
    except Exception as e:
        st.error(f"Error al cargar el archivo: {e}")
        return None

# Función para analizar el CSV y generar contexto
def analyze_csv(df):
    # Limitar filas y columnas para evitar DoS
    max_rows = 1000
    max_cols = 30
    if df.shape[0] > max_rows or df.shape[1] > max_cols:
        st.warning(f"El dataset es grande. Solo se analizarán las primeras {max_rows} filas y {max_cols} columnas.")
        df = df.iloc[:max_rows, :max_cols]
    
    # Advertencia si hay columnas con nombres sensibles
    sensitive_keywords = ['name', 'email', 'phone', 'address', 'dni', 'ssn', 'credit', 'tarjeta', 'password', 'contraseña']
    for col in df.columns:
        for key in sensitive_keywords:
            if key in col.lower():
                st.warning(f"Advertencia: La columna '{col}' podría contener datos sensibles.")
    
    summary = f"El dataset contiene {len(df)} filas y {len(df.columns)} columnas.\n\n"
    summary += "Columnas disponibles:\n"
    for col in df.columns:
        summary += f"- {col}: {df[col].dtype}\n"
    
    summary += "\nResumen estadístico:\n"
    summary += str(df.describe(include='all'))
    
    # Muestra de datos para contexto
    sample_data = "\n\nPrimeras filas del dataset:\n"
    sample_data += df.head().to_string()
    
    return summary + sample_data

# Validar codificación y tipos de datos del CSV
def validate_csv_file(uploaded_file):
    if uploaded_file is None:
        st.error("No se ha subido ningún archivo.")
        return False
    if not uploaded_file.name.lower().endswith('.csv'):
        st.error("El archivo debe ser un CSV.")
        return False
    if uploaded_file.size > 5 * 1024 * 1024:  # 5 MB
        st.error("El archivo es demasiado grande (máx. 5MB).")
        return False
    # Validar codificación
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    encoding = chardet.detect(raw)['encoding']
    if encoding is None or encoding.lower() != 'utf-8':
        st.error("El archivo debe estar en codificación UTF-8.")
        return False
    uploaded_file.seek(0)
    # Validación de contenido: intentar leer solo 5 filas
    try:
        df = pd.read_csv(uploaded_file, nrows=5, encoding='utf-8')
        if df.empty or len(df.columns) == 0:
            st.error("El archivo no contiene datos válidos.")
            return False
        # Validar tipos de datos
        for col in df.columns:
            if df[col].dtype not in ["int64", "float64", "object"]:
                st.warning(f"Columna '{col}' con tipo de dato inusual: {df[col].dtype}")
            # Validar caracteres peligrosos en los campos
            if df[col].astype(str).str.contains(r'[<>!#`\\]', regex=True).any():
                st.warning(f"Columna '{col}' contiene caracteres potencialmente peligrosos.")
    except Exception as e:
        st.error("El archivo no es un CSV válido.")
        logger.error(f"Error validando CSV: {e}")
        return False
    uploaded_file.seek(0)
    return True

# Filtrar palabras peligrosas y estructuras de prompt injection
def filter_prompt_injection(text):
    blacklist = [
        r"\\x00-\\x1f\\x7f-\\x9f", r"[<>]", r"!", r"#!", r"sh", r"`+", r"\\", r"system", r"assistant", r"user", r"inst", r"prompt", r"import", r"os", r"exec", r"eval", r"open", r"subprocess", r"token", r"api", r"key", r"bypass", r"reset", r"role:", r"content:", r"python", r"exit", r"quit", r"del", r"remove", r"delete", r"sudo", r"root", r"admin", r"shell", r"cmd", r"powershell"
    ]
    for word in blacklist:
        text = re.sub(rf'(?i){word}', '[filtrado]', text)
    return text

# Sanitizar entrada del usuario para evitar inyecciones
def sanitize_user_input(user_input):
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', user_input)
    sanitized = sanitized.strip()
    sanitized = sanitized[:500]
    sanitized = filter_prompt_injection(sanitized)
    return sanitized

# Límite de tasa por sesión
import time
def rate_limit():
    now = time.time()
    if 'last_query' in st.session_state:
        if now - st.session_state['last_query'] < 2:  # 2 segundos entre preguntas
            st.error("Por favor, espera un momento antes de enviar otra pregunta.")
            return False
    st.session_state['last_query'] = now
    return True

# Función para consultar a Groq
def query_groq(user_query, csv_context, api_key):
    # Limitar tamaño del contexto para evitar abusos
    max_context_length = 3000
    csv_context = csv_context[:max_context_length]
    user_query = sanitize_user_input(user_query)
    # Escapar caracteres especiales
    csv_context = re.sub(r'[<>]', '', csv_context)
    user_query = re.sub(r'[<>]', '', user_query)
    # Validar que la API Key venga de variable de entorno si existe
    api_key_env = os.environ.get('GROQ_API_KEY')
    if api_key_env:
        api_key = api_key_env
    
    client = Groq(api_key=api_key)
    
    prompt = f"""
    Eres un experto analista de datos. A continuación tienes información sobre un dataset CSV:
    
    {csv_context}
    
    Responde de manera clara y precisa a la siguiente pregunta del usuario:
    {user_query}
    
    Si la pregunta requiere cálculos o análisis específicos del dataset:
    1. Explica cómo calcularías la respuesta
    2. Proporciona la respuesta estimada basada en los datos disponibles
    3. Si faltan detalles, indica qué información adicional necesitarías
    
    Proporciona respuestas completas pero concisas, con formato claro.
    """
    
    completion = client.chat.completions.create(
        model="llama3-70b-8192",  # Modelo actualizado
        messages=[
            {"role": "system", "content": "Eres un asistente experto en análisis de datos con capacidad para interpretar datasets CSV."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
        max_tokens=2048,  # Aumentado para respuestas más completas
        top_p=1,
        stream=False,
        stop=None,
    )
    
    return completion.choices[0].message.content

# Función para escapar caracteres HTML
def escape_html(text):
    return re.sub(r'[&<>"\']', lambda m: {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[m.group()], text)

# Interfaz de usuario con Streamlit
def main():
    try:
        st.title("📊 Analizador de CSV con Groq")
        st.write("Sube un archivo CSV y haz preguntas sobre sus datos")
        # Sidebar para configuración
        with st.sidebar:
            st.header("Configuración")
            api_key = st.text_input("Introduce tu API Key de Groq", type="password")
            model_choice = st.selectbox(
                "Modelo a utilizar",
                ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768"],
                index=0
            )
            st.info("Necesitas una API Key de Groq para usar esta aplicación.")
            st.markdown("[Obtén tu API Key aquí](https://console.groq.com/keys)")
        uploaded_file = st.file_uploader("Sube tu archivo CSV", type=["csv"])
        if uploaded_file is not None:
            if not validate_csv_file(uploaded_file):
                return
            df = load_csv(uploaded_file)
            if df is not None:
                st.success("Archivo CSV cargado correctamente!")
                st.subheader("Vista previa del dataset")
                st.dataframe(df.head())
                csv_context = analyze_csv(df)
                if 'history' not in st.session_state:
                    st.session_state.history = []
                with st.form(key="query_form"):
                    user_query = st.text_area("Haz una pregunta sobre los datos", 
                                            placeholder="Ej: ¿Cuál es la correlación entre X e Y?", max_chars=500)
                    submit_button = st.form_submit_button("Enviar pregunta")
                if submit_button and user_query:
                    if not api_key:
                        st.error("Por favor, introduce tu API Key de Groq en la barra lateral")
                    elif not rate_limit():
                        return
                    else:
                        with st.spinner("Analizando tu pregunta..."):
                            try:
                                response = query_groq(user_query, csv_context, api_key)
                                st.session_state.history.append((escape_html(sanitize_user_input(user_query)), escape_html(response)))
                                st.subheader("Respuesta")
                                st.markdown(escape_html(response), unsafe_allow_html=False)
                                with st.expander("Ver detalles técnicos del análisis"):
                                    st.text(csv_context)
                                logger.info(f"Pregunta realizada: {user_query}")
                            except Exception as e:
                                st.error("Error al consultar Groq. Intenta de nuevo más tarde.")
                                logger.error(f"Error al consultar Groq: {e}")
                if st.session_state.history:
                    st.subheader("Historial de preguntas")
                    for i, (q, a) in enumerate(st.session_state.history, 1):
                        with st.expander(f"Pregunta {i}: {q}"):
                            st.markdown(a, unsafe_allow_html=False)
    except Exception as e:
        st.error("Error inesperado en la aplicación. Contacta al administrador.")
        logger.error(f"Error inesperado: {e}")
        st.stop()

if __name__ == "__main__":
    main()