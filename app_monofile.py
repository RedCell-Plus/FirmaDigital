# app_con_interfaz.py - Firma Digital en PDF con Interfaz Gráfica
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import PyPDF2
import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

# Configuración inicial de directorios
os.makedirs("keys", exist_ok=True)
os.makedirs("pdfs", exist_ok=True)

class FirmaDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Documento con Firma Digital PDF - ISO/IEC 27032 - Juan Manuel/Luis Mario")
        self.root.geometry("800x600")
        
        # Variables
        self.private_key = None
        self.autores_var = tk.StringVar()
        self.mensaje_var = tk.StringVar()
        self.resultado_var = tk.StringVar()
        
        # Crear interfaz
        self.crear_interfaz()
    
    def crear_interfaz(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Sección de autores
        ttk.Label(main_frame, text="Autores:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.autores_entry = ttk.Entry(main_frame, textvariable=self.autores_var, width=50)
        self.autores_entry.grid(row=0, column=1, sticky=tk.W, pady=(0, 5))
        self.autores_var.set("Juan Manuel & Luis Mario")
        
        # Sección de mensaje
        ttk.Label(main_frame, text="Mensaje a firmar:").grid(row=1, column=0, sticky=tk.NW, pady=(0, 5))
        self.mensaje_text = ScrolledText(main_frame, width=60, height=5, wrap=tk.WORD)
        self.mensaje_text.grid(row=1, column=1, sticky=tk.W, pady=(0, 10))
        self.mensaje_text.insert(tk.END, "Por medio de la presente se certifica que este documento ha sido revisado y aprobado por los responsables mencionados.")
        
        # Botones de acción
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Generar Claves", command=self.generar_claves).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Firmar y Crear PDF", command=self.firmar_y_crear_pdf).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Verificar Firma", command=self.verificar_firma).pack(side=tk.LEFT, padx=5)
        
        # Área de resultados
        ttk.Label(main_frame, text="Resultado:").grid(row=3, column=0, sticky=tk.NW, pady=(10, 0))
        self.resultado_text = ScrolledText(main_frame, width=60, height=10, wrap=tk.WORD)
        self.resultado_text.grid(row=3, column=1, sticky=tk.W, pady=(10, 0))
        self.resultado_text.config(state=tk.DISABLED)
        
        # Información sobre la aplicación
        info_frame = ttk.LabelFrame(main_frame, text="Información", padding=10)
        info_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=(20, 0))
        
        info_text = """Esta aplicación implementa firmas digitales según ISO/IEC 27032:
- Genera un par de claves RSA 2048-bit
- Firma digitalmente un mensaje con codificacion SHA-256 utfm8 y decodificacion exponente 65537 rsa 
- Crea un PDF con la firma incrustada
- Verifica la autenticidad e integridad del documento
1. Ingrese los nombres de los responsables
2. Escriba el mensaje a firmar
3. Genere las claves (solo una vez)
4. Cree el PDF firmado
5. Puede verificar la firma en cualquier momento"""
        
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)
    
    def mostrar_resultado(self, texto):
        self.resultado_text.config(state=tk.NORMAL)
        self.resultado_text.delete(1.0, tk.END)
        self.resultado_text.insert(tk.END, texto)
        self.resultado_text.config(state=tk.DISABLED)
    
    def generar_claves(self):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Guardar clave privada (protegida)
            with open("keys/private_key.pem", "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b'password123')
                ))
            
            # Guardar clave pública
            with open("keys/public_key.pem", "wb") as f:
                f.write(self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            self.mostrar_resultado("✅ Claves generadas y guardadas en la carpeta 'keys'")
            messagebox.showinfo("Éxito", "Claves generadas correctamente")
        except Exception as e:
            self.mostrar_resultado(f"❌ Error al generar claves: {str(e)}")
            messagebox.showerror("Error", f"No se pudieron generar las claves:\n{str(e)}")
    
    def firmar_mensaje(self, mensaje: str):
        if not self.private_key:
            try:
                # Intentar cargar la clave privada si existe
                with open("keys/private_key.pem", "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=b'password123',
                        backend=default_backend()
                    )
            except:
                messagebox.showerror("Error", "No hay claves generadas. Genere las claves primero.")
                return None
        
        try:
            firma = self.private_key.sign(
                mensaje.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(firma).decode()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo firmar el mensaje:\n{str(e)}")
            return None
    
    def crear_pdf(self, mensaje: str, firma: str, autores: str):
        try:
            # Preguntar dónde guardar el PDF
            filepath = filedialog.asksaveasfilename(
                initialdir="pdfs",
                title="Guardar PDF como",
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")]
            )
            
            if not filepath:
                return None
            
            c = canvas.Canvas(filepath, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, 750, "Documento con Firma Digital (ISO/IEC 27032)")
            
            # Información sobre firmas
            c.setFont("Helvetica", 12)
            info = [
                "Firma digital garantiza:",
                "- Autenticidad: Verifica la identidad del autor.",
                "- Integridad: El documento no ha sido alterado.",
                "- No repudio: El autor no puede negar la autoría.",
                "",
                "Empresas que usan esta tecnología:",
                "• Bancos (BBVA, Santander)",
                "• SAT (México), Adobe Sign",
                "• Plataformas de contratos electrónicos"
            ]
            y = 700
            for line in info:
                c.drawString(100, y, line)
                y -= 20
            
            # Autores y firma
            c.drawString(100, 500, f"Autores: {autores}")
            c.drawString(100, 480, f"Mensaje firmado: {mensaje}")
            c.drawString(100, 460, f"Firma digital (Base64): {firma}")
            c.save()
            
            return filepath
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el PDF:\n{str(e)}")
            return None
    
    def firmar_y_crear_pdf(self):
        autores = self.autores_var.get()
        mensaje = self.mensaje_text.get("1.0", tk.END).strip()
        
        if not autores or not mensaje:
            messagebox.showwarning("Advertencia", "Debe ingresar autores y un mensaje")
            return
        
        firma = self.firmar_mensaje(mensaje)
        if firma:
            pdf_path = self.crear_pdf(mensaje, firma, autores)
            if pdf_path:
                self.mostrar_resultado(
                    f"✅ PDF firmado creado exitosamente:\n{pdf_path}\n\n"
                    f"Autores: {autores}\n"
                    f"Firma digital: {firma[:50]}... (truncada)"
                )
                messagebox.showinfo("Éxito", f"PDF creado en:\n{pdf_path}")
    
    def verificar_firma(self):
        filepath = filedialog.askopenfilename(
            initialdir="pdfs",
            title="Seleccionar PDF a verificar",
            filetypes=[("PDF files", "*.pdf")]
        )
        
        if not filepath:
            return
        
        try:
            with open(filepath, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                texto = "\n".join([page.extract_text() for page in reader.pages])
            
            # Extraer componentes
            autores = texto.split("Autores: ")[1].split("\n")[0]
            mensaje = texto.split("Mensaje firmado: ")[1].split("\n")[0]
            firma_b64 = texto.split("Firma digital (Base64): ")[1].split("\n")[0]
            
            # Cargar clave pública
            with open("keys/public_key.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            # Verificación
            try:
                public_key.verify(
                    base64.b64decode(firma_b64),
                    mensaje.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                resultado = f"✅ Firma válida\n\nAutores: {autores}\nMensaje: {mensaje}"
                messagebox.showinfo("Verificación Exitosa", "La firma digital es válida")
            except Exception as e:
                resultado = f"❌ Firma inválida (posible alteración)\n\nError: {str(e)}"
                messagebox.showerror("Error de Verificación", "La firma no es válida o el documento ha sido alterado")
            
            self.mostrar_resultado(resultado)
        except Exception as e:
            self.mostrar_resultado(f"❌ Error al verificar el PDF: {str(e)}")
            messagebox.showerror("Error", f"No se pudo verificar el PDF:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirmaDigitalApp(root)
    root.mainloop()
