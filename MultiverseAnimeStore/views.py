from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.generic import ListView, CreateView, UpdateView, DeleteView, DetailView
from django.urls import reverse_lazy
from .models import Categoria, Contactos, Pedidos, PedidosProductos, Productos, Roles, Perfiles, Perfilpermisos, Modulos, Usuarios, Sexos, EstadoPedidos, Config_Contacto, Productos_Auditoria, Consultas_Dinamicas
from .forms import PedidosForm, UsuariosForm, RolesForm, PerfilesForm, CategoriaForm, ProductosForm, PedidoProductoUpdateForm, ConsultasDinamicasForm, EstadoPedidosForm, SexosForm, PerfilForm, CambiarContrasenaForm, next_int_id
from django.db.models import F, ExpressionWrapper, DecimalField, Sum, Q, Max, Count
from django.http import HttpResponseRedirect, JsonResponse
from django.db import DatabaseError, transaction, connection
from django.core.exceptions import ValidationError
from . import hidden_products
from django.contrib import messages
import re
import logging
from functools import wraps
from django.forms import modelform_factory
# import psycopg2
import json
import secrets
from datetime import date, timedelta
from decimal import Decimal
from django.db.models.functions import TruncWeek, TruncMonth
from django.core.paginator import Paginator
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

# @method_decorator(Permisos_Admin, name='dispatch')

def Permisos_Admin(modulo, tipo, redirect_url='admin_home'):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):


            if not getattr(request.user, 'is_authenticated', False):
                return redirect('login')
            
            

            usuario = Usuarios.objects.filter(id_usuario=request.user.id_usuario).first()
            if not usuario or not usuario.usuario_id_perfil:
                messages.error(request, 'No tienes perfil asignado. Contacta al administrador.')
                return redirect(redirect_url)

            perfil = usuario.usuario_id_perfil
            modulo_obj = Modulos.objects.filter(nombre_mod__iexact=modulo).first()
            if not modulo_obj:
                messages.error(request, f'Módulo "{modulo}" no configurado.')
                return redirect(redirect_url)

            permiso_obj = Perfilpermisos.objects.filter(perfil_id=perfil, mod_id=modulo_obj).first()
            if not permiso_obj:
                messages.error(request, 'No tienes permiso para acceder a este módulo.')
                return redirect(redirect_url)

            permiso_value = getattr(permiso_obj, f'can_{tipo}', None)
            if permiso_value != 'Y':
                messages.error(request, f'No tienes permiso para {tipo} en este módulo.')
                return redirect(redirect_url)

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def Login_requerido():
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):



            if not getattr(request.user, 'is_authenticated', False):
                return redirect('login')
            


            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator

# Función para extraer mensajes de error de BD (compatible PostgreSQL y otros)
def _extract_db_message(exc):
    """Extrae el mensaje amigable de una excepción de base de datos."""
    text = str(exc) or ''
    
    # PostgreSQL: buscar después de "DETAIL:" o "HINT:" o "ERROR:"
    for prefix in ['DETAIL:  ', 'HINT:  ', 'ERROR:  ', 'CONTEXT:  ']:
        if prefix in text:
            idx = text.find(prefix) + len(prefix)
            end = text.find('\n', idx)
            return text[idx:end].strip() if end > 0 else text[idx:].strip()
    
    # Fallback: primera línea no vacía que no parezca traceback
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('[') and not line.startswith('Traceback'):
            if len(line) > 10 and line[0].isupper():  # parece un mensaje real
                return line
    
    # Último recurso
    return text.strip() or 'Error de base de datos.'

@Login_requerido()
def admin_home(request):
    return render(request, 'admin_home.html')


# contraseña hashing 
def hash_password(password):
    """Hash de contraseña compatible con Django (bcrypt/PBKDF2)."""
    from django.contrib.auth.hashers import make_password
    return make_password(password)


def _verify_password(password, password_hash):
    """Verifica contraseña: soporta bcrypt (nuevo) y SHA-256 (viejo).
    Si coincide con SHA-256, retorna True pero el llamador debe re-hashear.
    """
    from django.contrib.auth.hashers import check_password
    # 1. Intentar con Django (bcrypt/PBKDF2)
    if check_password(password, password_hash):
        return 'modern'
    # 2. Fallback SHA-256 (contraseñas antiguas)
    import hashlib
    if hashlib.sha256(password.encode('utf-8')).hexdigest() == password_hash:
        return 'legacy'
    return False

# Login
def login_view(request):
    # Si ya está autenticado, redirigir al catálogo (no mostrar login)
    if request.user.is_authenticated:
        return redirect('catalogo')

    if request.method == 'POST':
        usuario = request.POST.get('usuario')
        contraseña = request.POST.get('contraseña')

        try:
            user = Usuarios.objects.get(id_usuario=usuario)
            result = _verify_password(contraseña, user.password_hash)
            if not result:
                raise Usuarios.DoesNotExist

            # Si es contraseña vieja (SHA-256), migrar a bcrypt ahora
            if result == 'legacy':
                user.password_hash = hash_password(contraseña)
                user.save(update_fields=['password_hash'])

            request.session['user_id'] = user.id_usuario

            # Validar open redirect: next debe empezar con /
            destino = request.POST.get('next', '')
            if not destino.startswith('/'):
                destino = 'catalogo'
            return redirect(destino)
        except Usuarios.DoesNotExist:
            messages.error(request, 'Credenciales inválidas. Inténtalo de nuevo.')

    return render(request, 'Sesion/login.html', {'sidebar': 0})

# registro 
def register_view(request):
    if request.method == 'POST':
        usuario = request.POST.get('usuario')
        contraseña = request.POST.get('contraseña')
        nombre = request.POST.get('nombre')
        primer_apellido = request.POST.get('primer_apellido')
        segundo_apellido = request.POST.get('segundo_apellido')
        fecha_nacimiento = request.POST.get('fecha_nacimiento') or None
        sexo_id = request.POST.get('sexo')
        telefono = request.POST.get('telefono', '').strip()
        direccion = request.POST.get('direccion', '').strip()

        if not telefono:
            messages.error(request, 'El teléfono es obligatorio.')
            return render(request, 'Sesion/register.html', {'Sexos': Sexos.objects.values('id_sexo', 'nombre_sexo')})

        if Usuarios.objects.filter(id_usuario=usuario).exists():
            messages.error(request, 'El nombre de usuario ya existe. Elige otro.')
        else:
            sexo = get_object_or_404(Sexos, pk=sexo_id)
            perfil_cliente = Perfiles.objects.filter(id_perfil=2).first()

            user = Usuarios.objects.create(
                id_usuario=usuario,
                password_hash=hash_password(contraseña),
                nombre=nombre,
                primer_apellido=primer_apellido,
                segundo_apellido=segundo_apellido,
                fecha_nacimiento=fecha_nacimiento,
                usuario_id_sexo=sexo,
                usuario_id_perfil=perfil_cliente,
                activo=1
            )

            from .forms import next_int_id
            Contactos.objects.create(
                id_contacto=next_int_id(Contactos, 'id_contacto'),
                dato_contacto=telefono,
                tipo_contacto_id=1,
                id_usuario=user,
            )

            if direccion:
                Contactos.objects.create(
                    id_contacto=next_int_id(Contactos, 'id_contacto'),
                    dato_contacto=direccion,
                    tipo_contacto_id=3,
                    id_usuario=user,
                )

            messages.success(request, 'Registro exitoso. Ahora puedes iniciar sesión.')
            return redirect('login')

    Sexo = Sexos.objects.values('id_sexo', 'nombre_sexo')

    return render(request, 'Sesion/register.html', {'Sexos': Sexo})

# logout
def logout_view(request):
    request.session.flush()
    messages.success(request, 'Has cerrado sesión. ¡Vuelve pronto!')
    return redirect(reverse('home') + '?clear_cart=1')

#Categorias

@method_decorator(Permisos_Admin('Categoria', 'read'), name='dispatch')
class CategoriaListView(ListView):
    model = Categoria
    template_name = 'Categoria/categoria_list.html'

@method_decorator(Permisos_Admin('Categoria', 'read'), name='dispatch')
class CategoriaDetailView(DetailView):
    model = Categoria
    template_name = 'Categoria/categoria_detail.html'

@method_decorator(Permisos_Admin('Categoria', 'delete'), name='dispatch')
class CategoriaDeleteView(DeleteView):
    model = Categoria
    template_name = 'Categoria/categoria_confirm_delete.html'
    success_url = reverse_lazy('categoria_list')

    def delete(self, request, *args, **kwargs):
        categoria = self.get_object()
        if Productos.objects.filter(cat=categoria).exists():
            messages.error(request, f'No se puede eliminar "{categoria.cat_nombre}" porque tiene productos asociados.')
            return redirect('categoria_list')
        return super().delete(request, *args, **kwargs)

@Permisos_Admin('Categoria', 'create')
def CategoriaCreateView(request):
    if request.method == 'POST':
        form = CategoriaForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('categoria_list')
    else:
        form = CategoriaForm()
    return render(request, 'Categoria/categoria_form.html', {'form': form})

@Permisos_Admin('Categoria', 'update')
def CategoriaUpdateView(request, pk):
    categoria = get_object_or_404(Categoria, pk=pk)
    if request.method == 'POST':
        form = CategoriaForm(request.POST, instance=categoria)
        if form.is_valid():
            form.save()
            return redirect('categoria_list')
    else:
        form = CategoriaForm(instance=categoria)
    return render(request, 'Categoria/categoria_form.html', {'form': form, 'object': categoria})


def desactivar_trigger():
    pass

def activar_trigger():
    pass


#PedidosProductos
def PedidosProductosCreateView(productos_seleccionados, id_pedido):

    with transaction.atomic():

        for item in productos_seleccionados:
            prod_id, cantidad = item.split(',')
            producto = get_object_or_404(Productos, pk=prod_id)
            pedido = get_object_or_404(Pedidos, pk=id_pedido)

            pped_precio_unitario = producto.prod_precio_venta
            pped_descuento = producto.prod_descuento
            pped_cantidad = int(cantidad)
            pped_total = (pped_precio_unitario - (pped_precio_unitario * (pped_descuento/100))) * pped_cantidad

            pped_estado = get_object_or_404(EstadoPedidos, pk=1)  

            PedidosProductos.objects.create(
                ped=pedido,
                prod=producto,
                pped_cantidad=pped_cantidad,
                pped_precio_unitario=pped_precio_unitario,
                pped_total=pped_total,
                pped_descuento=pped_descuento,
                pped_estado=pped_estado
            )

        # VALIDACIÓN FINAL DEL PEDIDO (reemplazo de sp_cerrar_pedido de Oracle)
        # Calcular total actualizado del pedido basado en productos
        total_real = PedidosProductos.objects.filter(ped=pedido).aggregate(
            total=Sum('pped_total')
        )['total'] or 0
        Pedidos.objects.filter(pk=id_pedido).update(ped_total=total_real)
        


def PedidoProductoUpdateFormView(request, ped_id, prod_id):
    objeto = get_object_or_404(PedidosProductos, ped_id=ped_id, prod_id=prod_id)

    if request.method == 'POST':
        form = PedidoProductoUpdateForm(request.POST, instance=objeto)
        if form.is_valid():
            form.save()
            return redirect('pedidos_update', pk=ped_id)  # ajusta a tu URL final
    else:
        form = PedidoProductoUpdateForm(instance=objeto)

    return render(request, 'Pedidos/pedidos_productos_form.html', {
        'form': form,
        'objeto': objeto
    })

@Permisos_Admin('Pedidos', 'delete')
def PedidoProductoDeleteView(request, ped_id):
    

    for p in PedidosProductos.objects.filter(ped_id=ped_id):
        producto = get_object_or_404(Productos, pk=p.prod_id)
        producto.prod_stock = F('prod_stock') + p.pped_cantidad
        producto.save()
        p.delete()

    return redirect('pedidos_list')

#Pedidos

@method_decorator(Permisos_Admin('Pedidos', 'read'), name='dispatch')
class PedidosListView(ListView):
    model = Pedidos
    template_name = 'Pedidos/pedidos_list.html'
    paginate_by = 10

    def get_queryset(self):
        queryset = Pedidos.objects.all().order_by('ped_id')
        pedido_id = self.request.GET.get('pedido_id')

        if pedido_id:
            try:
                pedido_id_int = int(pedido_id)
                queryset = queryset.filter(ped_id=pedido_id_int)
            except ValueError:
                queryset = queryset.none()

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['pedido_id'] = self.request.GET.get('pedido_id', '')
        return context

@method_decorator(Permisos_Admin('Pedidos', 'read'), name='dispatch')
class PedidosDetailView(DetailView):
    model = Pedidos
    template_name = 'Pedidos/pedidos_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['contactos'] = Contactos.objects.filter(id_usuario=self.object.usu)
        return context

@Permisos_Admin('Pedidos', 'create')
def PedidosCreateView(request):
    Json = {}

    if request.method == 'POST':
        productos_seleccionados = request.POST.getlist('productos_seleccionados')
        id_pedido = request.POST.get('ped_id')

        form = PedidosForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    pedido = form.save()
                    # crear relaciones dentro de la misma transacción
                    PedidosProductosCreateView(productos_seleccionados, id_pedido)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('pedidos_list')
    else:
        Prod = Productos.objects.values('prod_id', 'prod_nombre', 'prod_precio_venta', 'prod_stock', 'prod_descuento')
        Json['Productos'] = Prod
        form = PedidosForm()
    # success_url = reverse_lazy('pedidos_list')
    
    Json['form'] = form
    
    return render(request, 'Pedidos/pedidos_form.html', Json )

@Permisos_Admin('Pedidos', 'update')
def PedidosUpdateView(request, pk):
    pedido = get_object_or_404(Pedidos, pk=pk)
    productos_relacionados = PedidosProductos.objects.filter(ped=pedido)

    # Obtener estado del pedido (reemplazo de fn_estado_pedido de Oracle)
    Estado = pedido.ped_estado
        


    if request.method == 'POST':
        form = PedidosForm(request.POST, instance=pedido)
        if form.is_valid():
            try:
                with transaction.atomic():
                    pedido = form.save()
                    # si en edición recibes productos nuevos, manejarlos aquí (opcional)
                    productos_seleccionados = request.POST.getlist('productos_seleccionados')
                    if productos_seleccionados:
                        PedidosProductosCreateView(productos_seleccionados, pedido.ped_id)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('pedidos_list')
    else:
        form = PedidosForm(instance=pedido)

    return render(request, 'Pedidos/pedidos_form.html', {
        'form': form,
        'object': pedido,
        'productos_relacionados': productos_relacionados,
        'Estado': Estado,
    })

@Permisos_Admin('Pedidos', 'delete')
def PedidosDeleteView(request, pk):
    pedido = get_object_or_404(Pedidos, pk=pk)
    # pedidos_productos_relacionados = PedidosProductos.objects.filter(ped=pedido)
    
    try:
        # pedidos_productos_relacionados.delete()
        PedidoProductoDeleteView(request, pedido.ped_id)
        pedido.delete()
    except DatabaseError as e:
        messages.error(request, _extract_db_message(e))
        return redirect('pedidos_list')
    return redirect('pedidos_list')


#Productos
@method_decorator(Permisos_Admin('Productos', 'read'), name='dispatch')
class ProductosListView(ListView):
    model = Productos
    template_name = 'Productos/productos_list.html'


    paginate_by = 10

    def get_queryset(self):
        queryset = Productos.objects.all().order_by('prod_id')
        producto_id = self.request.GET.get('producto_id')

        if producto_id:
            # try:
            #     producto_id_int = int(producto_id)
            #     queryset = queryset.filter(prod_id=producto_id_int)
            # except ValueError:
            #     queryset = queryset.none()
            queryset = queryset.filter(prod_nombre__icontains=producto_id)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['producto_id'] = self.request.GET.get('producto_id', '')
        context['hidden_ids'] = hidden_products.get_hidden_product_ids()
        return context

@method_decorator(Permisos_Admin('Productos', 'read'), name='dispatch')
class ProductosDetailView(DetailView):
    model = Productos
    template_name = 'Productos/productos_detail.html'

PLACEHOLDER_IMAGES = [
    {'name': 'Figuras de Acción', 'url': '/static/MultiverseAnimeStore/placeholders/figuras.png'},
    {'name': 'Manga', 'url': '/static/MultiverseAnimeStore/placeholders/manga.png'},
    {'name': 'Accesorios', 'url': '/static/MultiverseAnimeStore/placeholders/accesorios.png'},
    {'name': 'Ropa', 'url': '/static/MultiverseAnimeStore/placeholders/ropa.png'},
    {'name': 'Tarjetas TCG', 'url': '/static/MultiverseAnimeStore/placeholders/tcg.png'},
    {'name': 'Peluches', 'url': '/static/MultiverseAnimeStore/placeholders/peluches.png'},
    {'name': 'Pósters', 'url': '/static/MultiverseAnimeStore/placeholders/posters.png'},
    {'name': 'Genérico (Grid)', 'url': '/static/MultiverseAnimeStore/placeholders/generic_1.png'},
    {'name': 'Genérico (Triángulos)', 'url': '/static/MultiverseAnimeStore/placeholders/generic_2.png'},
    {'name': 'Genérico (Ondas)', 'url': '/static/MultiverseAnimeStore/placeholders/generic_3.png'},
]

@Permisos_Admin('Productos', 'create')
def ProductosCreateView(request):
    if request.method == 'POST':
        form = ProductosForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('productos_list')
    else:
        form = ProductosForm()
    return render(request, 'Productos/productos_form.html', {
        'form': form,
        'placeholder_images': PLACEHOLDER_IMAGES,
    })

@Permisos_Admin('Productos', 'update')
def ProductosUpdateView(request, pk):
    producto = get_object_or_404(Productos, pk=pk)
    if request.method == 'POST':
        form = ProductosForm(request.POST, request.FILES, instance=producto)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('productos_list')
    else:
        form = ProductosForm(instance=producto)
    return render(request, 'Productos/productos_form.html', {
        'form': form,
        'object': producto,
        'placeholder_images': PLACEHOLDER_IMAGES,
        'producto_oculto': hidden_products.is_product_hidden(pk),
    })

@method_decorator(Permisos_Admin('Productos', 'delete'), name='dispatch')
class ProductosDeleteView(DeleteView):
    model = Productos
    template_name = 'productos_confirm_delete.html'
    success_url = reverse_lazy('productos_list')


@Login_requerido()
def toggle_producto_hidden(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta acción.')
        return redirect('home')
    action = hidden_products.toggle_product_hidden(pk)
    producto = Productos.objects.filter(pk=pk).first()
    nombre = producto.prod_nombre if producto else pk
    if action == 'hidden':
        messages.success(request, f'Producto "{nombre}" oculto del catálogo público.')
    else:
        messages.success(request, f'Producto "{nombre}" visible en el catálogo público.')
    referer = request.META.get('HTTP_REFERER', '')
    if referer:
        return redirect(referer)
    return redirect('panel_productos')


#productos auditoria
@Permisos_Admin('Productos', 'read')
def ProductosAuditoriaView(request):
    # productos_auditoria = Productos_Auditoria.objects.all()
    # productos_auditoria_raw = Productos_Auditoria.objects.raw(
    # "SELECT rownum AS id, creation_date, au_type, auditoria FROM productos_auditoria"
    # )

    productos_auditoria_raw = Productos_Auditoria.objects.raw("""
    SELECT 
        dummy_id,
        model_name,
        object_id,
        creation_date,
        au_type,
        auditoria
    FROM productos_auditoria
    ORDER BY creation_date DESC
    """)


# Convertimos los objetos y reemplazamos au_type por texto
    productos_auditoria = []
    for p in productos_auditoria_raw:
       if p.au_type == 1:
           p.au_type_text = "Creación"
       elif p.au_type == 2:
           p.au_type_text = "Modificación"
       elif p.au_type == 3:
           p.au_type_text = "Eliminación"
       else:
           p.au_type_text = "Desconocido"

       # Parsear el JSON de auditoria
       try:
           parsed = json.loads(p.auditoria)
           p.auditoria_parsed = parsed

           

           producto_info = parsed.get('old') if isinstance(parsed, dict) else None
           
           
        #    p.product_name = None
           if isinstance(producto_info, dict):
               
               p.product_name = producto_info.get('prod_nombre') or producto_info.get('nombre')
           elif isinstance(parsed, dict):
               p.product_name = parsed.get('prod_nombre') or parsed.get('nombre')

        #    print("DEBUG: Nombre del producto extraído:", p.product_name)
           
           if p.au_type == 2:  # Modificación
               old = parsed.get('old', {})
               new = parsed.get('new', {})
               differences = []
               for key in set(old.keys()) | set(new.keys()):
                   if old.get(key) != new.get(key):
                       differences.append({
                           'field': key,
                           'old': old.get(key, 'N/A'),
                           'new': new.get(key, 'N/A')
                       })
               p.differences = differences
           else:
               p.differences = []
       except json.JSONDecodeError:
           p.auditoria_parsed = None
           p.product_name = None
           p.differences = []

       productos_auditoria.append(p)

    if request.GET.get('format') == 'csv':
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
        response['Content-Disposition'] = 'attachment; filename="auditoria_productos.csv"'
        writer = csv.writer(response)
        writer.writerow(['Fecha', 'Tipo', 'Modelo', 'ID Objeto', 'Producto', 'Cambios'])
        for p in productos_auditoria:
            cambios = ''
            if p.au_type == 2 and getattr(p, 'differences', None):
                cambios = ' | '.join([f"{d['field']}: {d['old']} → {d['new']}" for d in p.differences])
            writer.writerow([
                p.creation_date.strftime('%Y-%m-%d %H:%M:%S') if p.creation_date else '',
                p.au_type_text,
                p.model_name,
                p.object_id,
                getattr(p, 'product_name', ''),
                cambios,
            ])
        return response

    return render(request, 'Productos/productos_auditoria.html', {'productos_auditoria': productos_auditoria})


@Login_requerido()
def panel_auditoria(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')

    # Reutilizar misma query
    productos_auditoria_raw = Productos_Auditoria.objects.raw("""
    SELECT
        dummy_id,
        model_name,
        object_id,
        creation_date,
        au_type,
        auditoria
    FROM productos_auditoria
    ORDER BY creation_date DESC
    """)

    productos_auditoria = []
    for p in productos_auditoria_raw:
        if p.au_type == 1:
            p.au_type_text = "Creación"
        elif p.au_type == 2:
            p.au_type_text = "Modificación"
        elif p.au_type == 3:
            p.au_type_text = "Eliminación"
        else:
            p.au_type_text = "Desconocido"
        try:
            parsed = json.loads(p.auditoria)
            p.auditoria_parsed = parsed
            producto_info = parsed.get('old') if isinstance(parsed, dict) else None
            if isinstance(producto_info, dict):
                p.product_name = producto_info.get('prod_nombre') or producto_info.get('nombre')
            elif isinstance(parsed, dict):
                p.product_name = parsed.get('prod_nombre') or parsed.get('nombre')
            else:
                p.product_name = None
            if p.au_type == 2:
                old = parsed.get('old', {})
                new = parsed.get('new', {})
                differences = []
                for key in set(old.keys()) | set(new.keys()):
                    if old.get(key) != new.get(key):
                        differences.append({'field': key, 'old': old.get(key, 'N/A'), 'new': new.get(key, 'N/A')})
                p.differences = differences
            else:
                p.differences = []
        except json.JSONDecodeError:
            p.auditoria_parsed = None
            p.product_name = None
            p.differences = []
        productos_auditoria.append(p)

    if request.GET.get('format') == 'csv':
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
        response['Content-Disposition'] = 'attachment; filename="auditoria_productos.csv"'
        writer = csv.writer(response)
        writer.writerow(['Fecha', 'Tipo', 'Modelo', 'ID Objeto', 'Producto', 'Cambios'])
        for p in productos_auditoria:
            cambios = ''
            if p.au_type == 2 and getattr(p, 'differences', None):
                cambios = ' | '.join([f"{d['field']}: {d['old']} → {d['new']}" for d in p.differences])
            writer.writerow([
                p.creation_date.strftime('%Y-%m-%d %H:%M:%S') if p.creation_date else '',
                p.au_type_text,
                p.model_name,
                p.object_id,
                getattr(p, 'product_name', ''),
                cambios,
            ])
        return response

    return render(request, 'Admin/panel_auditoria.html', {
        'productos_auditoria': productos_auditoria,
        'section': 'auditoria',
        'sidebar': 0,
    })

#Usuarios
@method_decorator(Permisos_Admin('Usuarios', 'read'), name='dispatch')
class UsuariosListView(ListView):
    model = Usuarios
    template_name = 'Usuarios/usuarios_list.html'

    paginate_by = 10

    def get_queryset(self):
        queryset = Usuarios.objects.all().order_by('id_usuario')
        usuario_id = self.request.GET.get('usuario_id')
        match_id = self.request.GET.get('match_id')

        if usuario_id:
            # try:
            #     producto_id_int = int(producto_id)
            #     queryset = queryset.filter(prod_id=producto_id_int)
            # except ValueError:
            #     queryset = queryset.none()
            if match_id:
                queryset = queryset.filter(id_usuario__iexact=usuario_id)
            else:
                queryset = queryset.filter(Q(nombre__icontains=usuario_id) | Q(id_usuario__icontains=usuario_id))

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['usuario_id'] = self.request.GET.get('usuario_id', '')
        context['match_id'] = self.request.GET.get('match_id', '')
        return context

@method_decorator(Permisos_Admin('Usuarios', 'read'), name='dispatch')
class UsuariosDetailView(DetailView):
    model = Usuarios
    template_name = 'Usuarios/usuarios_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['contactos'] = Contactos.objects.filter(id_usuario=self.object)
        return context

@Permisos_Admin('Usuarios', 'create')
def UsuariosCreateView(request):
    Json = {}

    if request.method == 'POST':
        contactos_relacionados = request.POST.getlist('contactos_relacionados')
        form = UsuariosForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    usuario = form.save()
                    # crear contactos dentro de la misma transacción
                    ContactosCreateView(contactos_relacionados, usuario.id_usuario)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('usuarios_list')
    else:
        form = UsuariosForm()
        
    Tipo_Contacto = Config_Contacto.objects.values('id_regla', 'nombre_contacto')
    Json['Tipo_Contacto'] = Tipo_Contacto
    Json['form'] = form
    return render(request, 'Usuarios/usuarios_form.html', Json )

@Permisos_Admin('Usuarios', 'update')
def UsuariosUpdateView(request, pk):
    usuario = get_object_or_404(Usuarios, pk=pk)
    contactos_relacionados = Contactos.objects.filter(id_usuario=usuario)
    
    if request.method == 'POST':
        form = UsuariosForm(request.POST, instance=usuario)
        contactos_relacionados_nuevo = request.POST.getlist('contactos_relacionados')
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                    # procesar contactos sólo si el guardado de usuario tuvo éxito
                    contactos_data = request.POST.getlist('contactos_relacionados_editados')
                    contactos_actualizar = []
                    for item in contactos_data:
                        parts = item.split(',')
                        if len(parts) == 3:
                            tipo_contacto, dato_contacto, id_contacto = parts
                            contactos_actualizar.append({
                                'id_contacto': id_contacto,
                                'tipo_contacto': tipo_contacto,
                                'dato_contacto': dato_contacto,
                            })
                        elif len(parts) == 2:
                            tipo_contacto, dato_contacto = parts
                            contactos_actualizar.append({
                                'tipo_contacto': tipo_contacto,
                                'dato_contacto': dato_contacto,
                            })
                    # actualizar y crear dentro de la transacción
                    if contactos_actualizar:
                        ContactosUpdateView(contactos_actualizar)
                    if contactos_relacionados_nuevo:
                        ContactosCreateView(contactos_relacionados_nuevo, usuario.id_usuario)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('usuarios_list')
    else:
        form = UsuariosForm(instance=usuario)

    Tipo_Contacto = Config_Contacto.objects.values('id_regla', 'nombre_contacto')
    
    return render(request, 'Usuarios/usuarios_form.html', {
        'form': form,
        'object': usuario,
        'contactos_relacionados': contactos_relacionados,
        'Tipo_Contacto': Tipo_Contacto,
    })

@Permisos_Admin('Usuarios', 'delete')
def UsuariosDeleteView(request, pk):
    usuario = get_object_or_404(Usuarios, pk=pk)
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # eliminar contactos ligados al usuario
                Contactos.objects.filter(id_usuario=usuario).delete()
                usuario.delete()
        except DatabaseError as e:
            messages.error(request, _extract_db_message(e))
            return redirect('usuarios_detail', pk=pk)
        return redirect('usuarios_list')
    # GET: mostrar confirmación
    return render(request, 'Usuarios/usuarios_confirm_delete.html', {'object': usuario})

#Contactos
@method_decorator(Permisos_Admin('Contactos', 'read'), name='dispatch')
class ContactosListView(ListView):
    model = Contactos
    template_name = 'Contactos/contactos_list.html'

@method_decorator(Permisos_Admin('Contactos', 'read'), name='dispatch')
class ContactosDetailView(DetailView):
    model = Contactos
    template_name = 'Contactos/contactos_detail.html'

# @Permisos_Admin('Contactos', 'create')
def ContactosCreateView(contactos_relacionados, id_usuario):
    errors = []
    for item in contactos_relacionados:
        try:
            id_con = Contactos.objects.count() + 1
            tipo_contacto, dato_contacto = item.split(',')
            tipo_contacto = get_object_or_404(Config_Contacto, pk=tipo_contacto)
            usuario = get_object_or_404(Usuarios, pk=id_usuario)
        
            Contactos.objects.create(
                id_contacto=id_con,
                tipo_contacto=tipo_contacto,
                dato_contacto=dato_contacto,
                id_usuario=usuario
            )
        except DatabaseError as e:
            errors.append(_extract_db_message(e))
        except Exception as e:
            errors.append(str(e))
    if errors:
        # lanzar un DatabaseError con el mensaje combinado para que lo capture la vista que llamó
        raise DatabaseError('; '.join(errors))

@Permisos_Admin('Contactos', 'update')
def ContactosUpdateView(contactos_actualizar):
    errors = []
    for contacto_data in contactos_actualizar:
        try:
            id_contacto = contacto_data['id_contacto']
            tipo_contacto_id = contacto_data['tipo_contacto']
            dato_contacto = contacto_data['dato_contacto']
            
            # Verificar que el contacto existe
            contacto = get_object_or_404(Contactos, pk=id_contacto)
            
            # Intentar deshabilitar auditorías/triggers a nivel de sesión
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL disable_auditoria_contactos = true")
                    cursor.execute("SET LOCAL disable_auditoria = true")

                    # Usar queryset.update() para forzar UPDATE sin insertar
                    resultado = Contactos.objects.filter(pk=id_contacto).update(
                        tipo_contacto_id=tipo_contacto_id,
                        dato_contacto=dato_contacto
                    )
            finally:
                # Restaurar el contexto de sesión
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL disable_auditoria_contactos = false")
                    cursor.execute("SET LOCAL disable_auditoria = false")

        except DatabaseError as e:
            errors.append(_extract_db_message(e))
        except Exception as e:
            errors.append(str(e))
    if errors:
        raise DatabaseError('; '.join(errors))

@Permisos_Admin('Contactos', 'delete')
def ContactosDeleteView(request, pk):
    contacto = get_object_or_404(Contactos, pk=pk)
    user_pk = contacto.id_usuario.pk if contacto.id_usuario else None
    try:
        contacto.delete()
    except DatabaseError as e:
        # mostrar sólo el mensaje del trigger y redirigir de vuelta al usuario (si aplica)
        messages.error(request, _extract_db_message(e))
        if user_pk:
            return redirect('usuarios_update', pk=user_pk)
        return redirect('usuarios_list')
    # si todo ok, volver a la edición del usuario cuando aplique
    if user_pk:
        return redirect('usuarios_update', pk=user_pk)
    return HttpResponseRedirect(reverse_lazy('usuarios_list'))

#Roles
@method_decorator(Permisos_Admin('Roles', 'read'), name='dispatch')
class RolesListView(ListView):
    model = Roles
    template_name = 'Roles/roles_list.html'

@method_decorator(Permisos_Admin('Roles', 'read'), name='dispatch')
class RolesDetailView(DetailView):
    model = Roles
    template_name = 'roles_detail.html'

@Permisos_Admin('Roles', 'create')
def RolesCreateView(request):
    if request.method == 'POST':
        form = RolesForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('roles_list')
    else:
        form = RolesForm()
    return render(request, 'Roles/roles_form.html', {'form': form})

@Permisos_Admin('Roles', 'update')
def RolesUpdateView(request, pk):
    role = get_object_or_404(Roles, pk=pk)
    if request.method == 'POST':
        form = RolesForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            return redirect('roles_list')
    else:
        form = RolesForm(instance=role)
    return render(request, 'Roles/roles_form.html', {'form': form, 'object': role})

@method_decorator(Permisos_Admin('Roles', 'delete'), name='dispatch')
class RolesDeleteView(DeleteView):
    model = Roles
    template_name = 'roles_confirm_delete.html'
    success_url = reverse_lazy('roles_list')


#perfiles 

@method_decorator(Permisos_Admin('Perfiles', 'read'), name='dispatch')
class PerfilesListView(ListView):
    model = Perfiles
    template_name = 'Perfiles/perfiles_list.html'

@method_decorator(Permisos_Admin('Perfiles', 'read'), name='dispatch')
class PerfilesDetailView(DetailView):
    model = Perfiles
    template_name = 'Perfiles/perfiles_detail.html'

@Permisos_Admin('Perfiles', 'create')
def PerfilesCreateView(request):
    if request.method == 'POST':
        form = PerfilesForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('perfiles_list')
    else:
        form = PerfilesForm()
    return render(request, 'Perfiles/perfiles_form.html', {'form': form})

@Permisos_Admin('Perfiles', 'update')
def PerfilesUpdateView(request, pk):
    perfil = get_object_or_404(Perfiles, pk=pk)
    if request.method == 'POST':
        form = PerfilesForm(request.POST, instance=perfil)
        if form.is_valid():
            form.save()
            return redirect('perfiles_list')
    else:
        form = PerfilesForm(instance=perfil)
    return render(request, 'Perfiles/perfiles_form.html', {'form': form, 'object': perfil})

@method_decorator(Permisos_Admin('Perfiles', 'delete'), name='dispatch')
class PerfilesDeleteView(DeleteView):
    model = Perfiles
    template_name = 'perfiles_confirm_delete.html'
    success_url = reverse_lazy('perfiles_list')


@Permisos_Admin('Perfiles', 'update')
def PerfilPermisosUpdateView(request, pk):
    perfil = get_object_or_404(Perfiles, pk=pk)
    modulos = Modulos.objects.all()

    if request.method == 'POST':
        # Para cada módulo, actualizar o crear el permiso
        for modulo in modulos:
            permiso_obj, created = Perfilpermisos.objects.get_or_create(
                perfil_id=perfil,
                mod_id=modulo
            )
            
            for tipo in ['read', 'create', 'update', 'delete']:
                field_name = f'perm_{modulo.nombre_mod}_{tipo}'
                setattr(permiso_obj, f'can_{tipo}', 'Y' if request.POST.get(field_name) == 'on' else 'N')
            
            permiso_obj.save()
        
        return redirect('perfiles_list')

    # Preparar datos para mostrar todos los módulos
    permisos_asignados = {}
    modulo_permisos = Perfilpermisos.objects.filter(perfil_id=perfil).select_related('mod_id')
    
    # Crear un diccionario de permisos existentes para búsqueda rápida
    permisos_dict = {mp.mod_id.id_mod: mp for mp in modulo_permisos}
    
    # Para cada módulo, obtener sus permisos (o valores por defecto)
    for modulo in modulos:
        if modulo.id_mod in permisos_dict:
            permiso = permisos_dict[modulo.id_mod]
            permisos_asignados[modulo.nombre_mod] = {
                'read': permiso.can_read == 'Y',
                'create': permiso.can_create == 'Y',
                'update': permiso.can_update == 'Y',
                'delete': permiso.can_delete == 'Y',
            }
        else:
            # Valores por defecto si no existe el permiso
            permisos_asignados[modulo.nombre_mod] = {
                'read': False,
                'create': False,
                'update': False,
                'delete': False,
            }

    return render(request, 'Perfiles/perfiles_permisos.html', {
        'perfil': perfil,
        'permisos_asignados': permisos_asignados,
    })



# Sexos
@method_decorator(Permisos_Admin('Sexos', 'read'), name='dispatch')
class SexosListView(ListView):
    model = Sexos
    template_name = 'Usuarios/sexos_list.html'

@method_decorator(Permisos_Admin('Sexos', 'read'), name='dispatch')
class SexosDetailView(DetailView):
    model = Sexos
    template_name = 'Usuarios/sexos_detail.html'

@method_decorator(Permisos_Admin('Sexos', 'create'), name='dispatch')
class SexosCreateView(CreateView):
    model = Sexos
    form_class = SexosForm
    template_name = 'Usuarios/sexos_form.html'
    success_url = reverse_lazy('sexos_list')

@method_decorator(Permisos_Admin('Sexos', 'update'), name='dispatch')
class SexosUpdateView(UpdateView):
    model = Sexos
    form_class = SexosForm
    template_name = 'Usuarios/sexos_form.html'
    success_url = reverse_lazy('sexos_list')

@method_decorator(Permisos_Admin('Sexos', 'delete'), name='dispatch')
class SexosDeleteView(DeleteView):
    model = Sexos
    template_name = 'Usuarios/sexos_confirm_delete.html'
    success_url = reverse_lazy('sexos_list')


#EstadoPedidos
@method_decorator(Permisos_Admin('EstadoPedidos', 'read'), name='dispatch')
class EstadoPedidosListView(ListView):
    model = EstadoPedidos
    template_name = 'Pedidos/estado_pedidos_list.html'

@method_decorator(Permisos_Admin('EstadoPedidos', 'read'), name='dispatch')
class EstadoPedidosDetailView(DetailView):
    model = EstadoPedidos
    template_name = 'estado_pedidos_detail.html'

@method_decorator(Permisos_Admin('EstadoPedidos', 'create'), name='dispatch')
class EstadoPedidosCreateView(CreateView):
    model = EstadoPedidos
    form_class = EstadoPedidosForm
    template_name = 'Pedidos/estado_pedidos_form.html'
    success_url = reverse_lazy('estado_pedidos_list')

@method_decorator(Permisos_Admin('EstadoPedidos', 'update'), name='dispatch')
class EstadoPedidosUpdateView(UpdateView):
    model = EstadoPedidos
    fields = '__all__'
    template_name = 'Pedidos/estado_pedidos_form.html'
    success_url = reverse_lazy('estado_pedidos_list')

@method_decorator(Permisos_Admin('EstadoPedidos', 'delete'), name='dispatch')
class EstadoPedidosDeleteView(DeleteView):
    model = EstadoPedidos
    template_name = 'Pedidos/estado_pedidos_confirm_delete.html'
    success_url = reverse_lazy('estado_pedidos_list')


# Config_Contacto CRUD
@method_decorator(Permisos_Admin('Config_Contactos', 'read'), name='dispatch')
class ConfigContactoListView(ListView):
    model = Config_Contacto
    template_name = 'Contactos/config_contacto_list.html'

@method_decorator(Permisos_Admin('Config_Contactos', 'read'), name='dispatch')
class ConfigContactoDetailView(DetailView):
    model = Config_Contacto
    template_name = 'Contactos/config_contacto_detail.html'

# Reemplaza la clase ConfigContactoCreateView por función que prellena id_regla
@Permisos_Admin('Config_Contactos', 'create')
def ConfigContactoCreateView(request):
    FormClass = modelform_factory(Config_Contacto, fields='__all__')
    if request.method == 'POST':
        form = FormClass(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                return redirect('config_contacto_list')
    else:
        initial = {'id_regla': Config_Contacto.next_id()}
        form = FormClass(initial=initial)
    return render(request, 'Contactos/config_contacto_form.html', {'form': form})

@method_decorator(Permisos_Admin('Config_Contactos', 'update'), name='dispatch')
class ConfigContactoUpdateView(UpdateView):
    model = Config_Contacto
    fields = '__all__'
    template_name = 'Contactos/config_contacto_form.html'
    success_url = reverse_lazy('config_contacto_list')

@method_decorator(Permisos_Admin('Config_Contactos', 'delete'), name='dispatch')
class ConfigContactoDeleteView(DeleteView):
    model = Config_Contacto
    template_name = 'Contactos/config_contacto_confirm_delete.html'
    success_url = reverse_lazy('config_contacto_list')


#Consultas_Dinamicas
@method_decorator(Permisos_Admin('Consultas', 'read'), name='dispatch')
class ConsultasDinamicasListView(ListView):
    model = Consultas_Dinamicas
    template_name = 'ConsultasDinamicas/consultas_dinamicas_list.html'

@method_decorator(Permisos_Admin('Consultas', 'read'), name='dispatch')
class ConsultasDinamicasDetailView(DetailView):
    model = Consultas_Dinamicas
    template_name = 'ConsultasDinamicas/consultas_dinamicas_detail.html'

@Permisos_Admin('Consultas', 'create')
def ConsultasDinamicasCreateView(request):
    if request.method == 'POST':
        # form = modelform_factory(ConsultasDinamicasForm, fields='__all__')(request.POST)
        form = ConsultasDinamicasForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('consultas_dinamicas_list')
    else:
        # form = modelform_factory(ConsultasDinamicasForm, fields='__all__')()
        form = ConsultasDinamicasForm()
    return render(request, 'ConsultasDinamicas/consultas_dinamicas_form.html', {'form': form})

# def ConsultasDinamicasUpdateView(request, pk):
#     consulta = get_object_or_404(Consultas_Dinamicas, pk=pk)
#     if request.method == 'POST':
#         # form = modelform_factory(ConsultasDinamicasForm, fields='__all__')(request.POST, instance=consulta)
#         form = ConsultasDinamicasForm(request.POST, instance=consulta)
#         if form.is_valid():
#             form.save()
#             return redirect('consultas_dinamicas_list')
#     else:
#         # form = modelform_factory(ConsultasDinamicasForm, fields='__all__')(instance=consulta)
#         form = ConsultasDinamicasForm(request.POST, instance=consulta)
#     return render(request, 'ConsultasDinamicas/consultas_dinamicas_form.html', {'form': form, 'object': consulta})

@method_decorator(Permisos_Admin('Consultas', 'update'), name='dispatch')
class ConsultasDinamicasUpdateView(UpdateView):
    model = Consultas_Dinamicas
    form_class = ConsultasDinamicasForm
    template_name = 'ConsultasDinamicas/consultas_dinamicas_form.html'
    success_url = reverse_lazy('consultas_dinamicas_list')

@method_decorator(Permisos_Admin('Consultas', 'delete'), name='dispatch')
class ConsultasDinamicasDeleteView(DeleteView):
    model = Consultas_Dinamicas
    template_name = 'ConsultasDinamicas/consultas_dinamicas_confirm_delete.html'
    success_url = reverse_lazy('consultas_dinamicas_list')


# def ejecutar_reporte(id_reporte):

#     with connection.cursor() as cursor:

#         # Cursor que recibirá el refcursor
#         out_cursor = cursor.connection.cursor()

#         # Llamar la función (retorna un refcursor)
#         ref = cursor.callfunc(
#             "pkg_reportes.fn_ejecutar_reporte",
#             oracledb.CURSOR,
#             [id_reporte]
#         )

#         columnas = [col[0] for col in ref.description]
#         resultados = []

#         for fila in ref:
#             resultados.append(dict(zip(columnas, fila)))

#         return resultados

def _sanitize_sql(sql):
    no_comments = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    no_comments = re.sub(r'--[^\n]*', '', no_comments)
    no_strings = re.sub(r"'[^']*'", "''", no_comments)
    no_strings = re.sub(r'"[^"]*"', '""', no_strings)
    return no_strings


@Permisos_Admin('Consultas', 'read')
def ejecutar_reporte(id_reporte):
    """
    Ejecuta una consulta dinamica guardada en Consultas_Dinamicas.
    Reemplazo de fn_ejecutar_reporte de Oracle.
    """
    try:
        consulta = Consultas_Dinamicas.objects.get(cons_id=id_reporte)
        sql = consulta.cons_sql.strip()

        sql_clean = _sanitize_sql(sql)

        if not re.match(r'^\s*SELECT\s', sql_clean, re.IGNORECASE):
            raise Exception('Solo se permiten consultas SELECT')

        if ';' in sql_clean:
            raise Exception('No se permiten multiples sentencias SQL')

        dangerous = re.findall(
            r'\b(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE|EXEC)\b',
            sql_clean,
            re.IGNORECASE
        )
        if dangerous:
            raise Exception(f'Comandos no permitidos: {", ".join(dangerous)}')

        with connection.cursor() as cursor:
            cursor.execute(sql)
            columnas = [col[0] for col in cursor.description]
            resultados = []
            for fila in cursor.fetchall():
                resultados.append(dict(zip(columnas, fila)))
            return resultados
    except Consultas_Dinamicas.DoesNotExist:
        return []
    except Exception as e:
        logging.error(f"Error ejecutando reporte {id_reporte}: {e}")
        return []

@Permisos_Admin('Consultas', 'read')
def reporte_view(request, id):
    data = ejecutar_reporte(id)
    return render(request, "ConsultasDinamicas/consultas_reporte.html", {"resultado": data})







def home_view(request):
    """Landing page: hero, categorías destacadas, últimos productos, redes sociales."""
    categorias = Categoria.objects.all()

    hidden_ids = hidden_products.get_hidden_product_ids()

    # Contar productos por categoría (para mostrar el badge)
    from django.db.models import Count
    categorias_conteo = Categoria.objects.annotate(
        productos_count=Count('productos')
    )

    # Top 4 categorías para hero cards (las que más productos tienen)
    hero_categories = categorias_conteo.order_by('-productos_count')[:4]

    # Productos destacados primero, luego los 8 más nuevos
    destacados = Productos.objects.select_related('cat').filter(prod_destacado=True).exclude(prod_id__in=hidden_ids).order_by('-prod_id')[:4]
    ultimos_productos = Productos.objects.select_related('cat').exclude(prod_id__in=hidden_ids).exclude(prod_id__in=[p.prod_id for p in destacados]).order_by('-prod_id')[:8]

    return render(request, 'Multiverse/landing.html', {
        'categorias': categorias_conteo,
        'hero_categories': hero_categories,
        'destacados': destacados,
        'ultimos_productos': ultimos_productos,
    })


def _guest_checkout_enabled():
    from .models import Configuracion
    try:
        return Configuracion.objects.get(clave='guest_checkout').valor != '0'
    except Exception:
        return True

def checkout_view(request):
    if request.method == 'POST':
        cart_items_json = request.POST.get('cart_items_json', '[]')

        try:
            cart_items = json.loads(cart_items_json)
        except json.JSONDecodeError:
            cart_items = []

        if not cart_items:
            messages.error(request, 'El carrito está vacío. No se creó ningún pedido.')
            return redirect(request.META.get('HTTP_REFERER', '/'))

        # ── DETERMINAR USUARIO ──────────────────────────────────────
        # Si está autenticado, usamos su usuario.
        # Si NO está autenticado (invitado), verificar si guest checkout está activo.
        # ─────────────────────────────────────────────────────────────
        if request.user.is_authenticated:
            usuario = request.user
        else:
            if not _guest_checkout_enabled():
                messages.error(request, 'Debes iniciar sesión para realizar un pedido.')
                return redirect('login')

            nombre_invitado = request.POST.get('nombre_invitado', '').strip()
            telefono_invitado = request.POST.get('telefono_invitado', '').strip()
            direccion_envio = request.POST.get('ped_direccion_envio', '').strip()

            if not nombre_invitado or not telefono_invitado:
                messages.error(request, 'Debes ingresar tu nombre y teléfono para continuar.')
                return redirect(request.META.get('HTTP_REFERER', '/'))

            from .forms import next_int_id, get_next_char_id

            with transaction.atomic():
                # ── Fase 2: Deduplicación por teléfono ──
                contacto_existente = Contactos.objects.filter(
                    dato_contacto=telefono_invitado,
                    id_usuario__activo=0
                ).select_related('id_usuario').first()

                if contacto_existente:
                    usuario = contacto_existente.id_usuario
                    if direccion_envio:
                        tiene_direccion = Contactos.objects.filter(
                            id_usuario=usuario, tipo_contacto_id=3
                        ).exists()
                        if not tiene_direccion:
                            Contactos.objects.create(
                                id_contacto=next_int_id(Contactos, 'id_contacto'),
                                dato_contacto=direccion_envio,
                                tipo_contacto_id=3,
                                id_usuario=usuario,
                            )
                else:
                    # ── Crear nuevo usuario invitado ──
                    next_id_num = get_next_char_id(Usuarios, 'id_usuario', 'USR-')
                    new_id = f"USR-{next_id_num}"

                    random_pass = secrets.token_hex(16)
                    hashed = hash_password(random_pass)

                    sexo_default = Sexos.objects.get(pk=3)
                    perfil_cliente = Perfiles.objects.get(pk=2)

                    partes_nombre = nombre_invitado.split(maxsplit=1)
                    nombre = partes_nombre[0] if partes_nombre else nombre_invitado
                    primer_apellido = partes_nombre[1] if len(partes_nombre) > 1 else "Invitado"

                    usuario = Usuarios.objects.create(
                        id_usuario=new_id,
                        nombre=nombre,
                        primer_apellido=primer_apellido,
                        password_hash=hashed,
                        activo=0,
                        usuario_id_sexo=sexo_default,
                        usuario_id_perfil=perfil_cliente,
                    )

                    # ── Fase 1: 2 contactos (teléfono + dirección) ──
                    Contactos.objects.create(
                        id_contacto=next_int_id(Contactos, 'id_contacto'),
                        dato_contacto=telefono_invitado,
                        tipo_contacto_id=1,
                        id_usuario=usuario,
                    )

                    if direccion_envio:
                        Contactos.objects.create(
                            id_contacto=next_int_id(Contactos, 'id_contacto'),
                            dato_contacto=direccion_envio,
                            tipo_contacto_id=3,
                            id_usuario=usuario,
                        )

            # NOTAS: ya no se marca [INVITADO - telefono] — los contactos son trazables
            notas_pedido = request.POST.get('ped_notas', '').strip()
            request.POST = request.POST.copy()
            request.POST['ped_notas'] = notas_pedido or 'Pedido creado desde carrito público'

        # ── FIN: usuario definido ─────────────────────────────────────

        productos_seleccionados = []
        total_calculado = Decimal('0.00')

        for item in cart_items:
            prod_id = item.get('id')
            qty = int(item.get('qty') or 0)
            if not prod_id or qty <= 0:
                continue

            producto = Productos.objects.filter(pk=prod_id).first()
            if not producto:
                continue

            productos_seleccionados.append(f"{prod_id},{qty}")
            precio_unitario = producto.prod_precio_venta or Decimal('0.00')
            descuento = producto.prod_descuento or Decimal('0.00')
            total_calculado += (precio_unitario - (precio_unitario * (descuento / Decimal('100')))) * qty

        if not productos_seleccionados:
            messages.error(request, 'No hay productos válidos en el carrito.')
            return redirect(request.META.get('HTTP_REFERER', '/'))

        try:
            with transaction.atomic():
                Pedidos.objects.select_for_update().first()
                next_ped_id = (Pedidos.objects.aggregate(max_id=Max('ped_id'))['max_id'] or 0) + 1
                pedido = Pedidos.objects.create(
                    ped_id=next_ped_id,
                    usu=usuario,
                    ped_fecha_pedido=date.today(),
                    ped_total=total_calculado,
                    ped_direccion_envio=request.POST.get('ped_direccion_envio', ''),
                    ped_notas=request.POST.get('ped_notas', 'Pedido creado desde carrito público'),
                )
                PedidosProductosCreateView(productos_seleccionados, pedido.ped_id)

        except (DatabaseError, ValidationError) as e:
            logging.error(f"Error al crear pedido: {e}")
            messages.error(request, _extract_db_message(e))
            return redirect(request.META.get('HTTP_REFERER', '/'))

        redirect_dest = 'mis_pedidos' if request.user.is_authenticated else 'home'
        messages.success(request, f'✅ Pedido #{pedido.ped_id} creado correctamente. Te contactaremos pronto.')
        return redirect(redirect_dest)

    return redirect('catalogo')


def catalogo_view(request):
    """Catálogo público con búsqueda por texto y filtro por categoría."""
    hidden_ids = hidden_products.get_hidden_product_ids()
    productos = Productos.objects.select_related('cat').exclude(prod_id__in=hidden_ids).order_by('prod_id')
    paginate_by = 40
    prod_nombre = request.GET.get('prod_nombre', '')
    cat_id = request.GET.get('cat', '')

    # ── Búsqueda por texto ──
    if prod_nombre:
        productos = productos.filter(
            Q(prod_nombre__icontains=prod_nombre) | Q(prod_descripcion__icontains=prod_nombre)
        )

    # ── Filtro por categoría ──
    if cat_id:
        productos = productos.filter(cat_id=cat_id)

    paginator = Paginator(productos, paginate_by)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Listado de categorías para mostrar como filtros en el catálogo
    categorias = Categoria.objects.all()

    return render(request, 'Multiverse/catalogo.html', {
        'productos': page_obj,
        'prod_nombre': prod_nombre,
        'cat_id': cat_id,
        'categorias': categorias,
    })


# ---------------------------------------------------------------------------
# PERFIL DEL CLIENTE - Mis Pedidos
# ---------------------------------------------------------------------------
@Login_requerido()
def mis_pedidos_view(request):
    """Muestra los pedidos del cliente logueado."""
    pedidos = Pedidos.objects.filter(usu=request.user).order_by('-ped_fecha_pedido')

    for pedido in pedidos:
        # Calcular el estado como texto
        pedido.estado_texto = pedido.ped_estado.est_nombre if pedido.ped_estado else 'Pendiente'
        pedido.productos_count = PedidosProductos.objects.filter(ped=pedido).count()

    return render(request, 'Multiverse/mis_pedidos.html', {
        'pedidos': pedidos,
        'sidebar': 0,
    })


@Login_requerido()
def pedido_detalle_view(request, ped_id):
    """Muestra el detalle de un pedido específico del cliente."""
    pedido = get_object_or_404(Pedidos, pk=ped_id, usu=request.user)

    pedido.estado_texto = pedido.ped_estado.est_nombre if pedido.ped_estado else 'Pendiente'

    productos = PedidosProductos.objects.filter(ped=pedido).select_related('prod', 'pped_estado')
    estados_timeline = [
        {'id': 1, 'nombre': 'Pendiente'},
        {'id': 2, 'nombre': 'Confirmado'},
        {'id': 3, 'nombre': 'Preparación'},
        {'id': 4, 'nombre': 'Enviado'},
        {'id': 5, 'nombre': 'Entregado'},
        {'id': 6, 'nombre': 'Cancelado'},
    ]

    return render(request, 'Multiverse/pedido_detalle.html', {
        'pedido': pedido,
        'productos': productos,
        'estados_timeline': estados_timeline,
        'sidebar': 0,
    })


@Login_requerido()
def mis_contactos_json_view(request):
    """Devuelve JSON con los contactos del usuario autenticado para pre-llenar el checkout."""
    usuario = request.user
    contactos = Contactos.objects.filter(id_usuario=usuario).select_related('tipo_contacto')
    data = {}
    for c in contactos:
        if c.tipo_contacto_id == 1:
            data['telefono'] = c.dato_contacto
        elif c.tipo_contacto_id == 3:
            partes = c.dato_contacto.split(' | ')
            data['calle'] = partes[0] if len(partes) > 0 else ''
            data['ciudad'] = partes[1] if len(partes) > 1 else ''
            data['barrio'] = partes[3] if len(partes) > 3 else (partes[2] if len(partes) == 3 else '')
    return JsonResponse(data)


# ---------------------------------------------------------------------------
# PERFIL DEL CLIENTE - Mi Perfil (datos personales + contactos)
# ---------------------------------------------------------------------------
@Login_requerido()
def mi_perfil_view(request):
    usuario = request.user
    contactos_usuario = Contactos.objects.filter(id_usuario=usuario).select_related('tipo_contacto')
    tipos_contacto = Config_Contacto.objects.all()

    contactos_por_tipo = {}
    for c in contactos_usuario:
        if c.tipo_contacto:
            contactos_por_tipo[c.tipo_contacto.pk] = c

    if request.method == 'POST' and 'cambiar_contrasena' in request.POST:
        pass_form = CambiarContrasenaForm(request.POST)
        if pass_form.is_valid():
            actual = pass_form.cleaned_data['contrasena_actual']
            verificacion = _verify_password(actual, usuario.password_hash)
            if not verificacion:
                messages.error(request, 'La contraseña actual es incorrecta.')
            else:
                usuario.password_hash = hash_password(pass_form.cleaned_data['contrasena_nueva'])
                usuario.save(update_fields=['password_hash'])
                messages.success(request, 'Contraseña actualizada correctamente.')
        else:
            for err in pass_form.errors.values():
                for e in err:
                    messages.error(request, e)
        return redirect('mi_perfil')

    if request.method == 'POST':
        form = PerfilForm(request.POST, instance=usuario)

        contactos_ok = True
        contactos_errors = []

        for tipo in tipos_contacto:
            contacto_existente = contactos_por_tipo.get(tipo.id_regla)

            if tipo.id_regla == 3:
                calle = request.POST.get('contacto_calle_3', '').strip()
                ciudad = request.POST.get('contacto_ciudad_3', '').strip()
                barrio = request.POST.get('contacto_barrio_3', '').strip()

                if not calle or not ciudad:
                    if contacto_existente:
                        contacto_existente.delete()
                    continue
                parts = [calle, ciudad]
                if barrio:
                    parts.append(barrio)
                dato = ' | '.join(parts)
            else:
                dato = request.POST.get(f'contacto_dato_{tipo.id_regla}', '').strip()

            if not dato:
                if contacto_existente:
                    contacto_existente.delete()
                continue

            min_len = int(tipo.min_length) if tipo.min_length else 0
            max_len = int(tipo.max_length) if tipo.max_length else 999

            if len(dato) < min_len or len(dato) > max_len:
                contactos_errors.append(tipo.mensaje_error or f'{tipo.nombre_contacto}: longitud inválida')
                contactos_ok = False
                continue

            try:
                if contacto_existente:
                    if contacto_existente.dato_contacto != dato:
                        contacto_existente.dato_contacto = dato
                        contacto_existente.save()
                else:
                    Contactos.objects.create(
                        id_contacto=next_int_id(Contactos, 'id_contacto'),
                        tipo_contacto=tipo,
                        dato_contacto=dato,
                        id_usuario=usuario,
                    )
            except DatabaseError as e:
                contactos_errors.append(_extract_db_message(e))
                contactos_ok = False

        if form.is_valid() and contactos_ok:
            form.save()
            messages.success(request, 'Perfil actualizado correctamente.')
            return redirect('mi_perfil')

        if contactos_errors:
            for err in contactos_errors:
                messages.error(request, err)

    else:
        form = PerfilForm(instance=usuario)

    tipos_con_contacto = []
    for t in tipos_contacto:
        c = contactos_por_tipo.get(t.id_regla)
        if t.id_regla == 3 and c and c.dato_contacto:
            partes = c.dato_contacto.split(' | ')
            if len(partes) == 4:
                addr_parts = {'calle': partes[0], 'ciudad': partes[1], 'barrio': partes[3]}
            elif len(partes) >= 2:
                addr_parts = {'calle': partes[0], 'ciudad': partes[1], 'barrio': partes[2] if len(partes) > 2 else ''}
            else:
                addr_parts = {'calle': c.dato_contacto, 'ciudad': '', 'barrio': ''}
        elif t.id_regla == 3:
            addr_parts = {'calle': '', 'ciudad': '', 'barrio': ''}
        else:
            addr_parts = None
        tipos_con_contacto.append((t, c, addr_parts))

    return render(request, 'Sesion/mi_perfil.html', {
        'form': form,
        'tipos_con_contacto': tipos_con_contacto,
        'sidebar': 0,
    })


# ─── Panel de Control (visor dark, capa aparte) ───

@Login_requerido()
def panel_dashboard(request):
    # Solo administradores (perfil_id=1) pueden ver el panel
    if not getattr(request.user, 'usuario_id_perfil_id', None) == 1:
        messages.error(request, 'No tienes permiso para acceder al panel de gestión.')
        return redirect('home')
    total_productos = Productos.objects.count()
    total_usuarios = Usuarios.objects.count()
    total_pedidos = Pedidos.objects.count()
    total_categorias = Categoria.objects.count()
    total_perfiles = Perfiles.objects.count()

    pedidos_pendientes = Pedidos.objects.filter(ped_estado_id=1).count()
    pedidos_confirmados = Pedidos.objects.filter(ped_estado_id=2).count()
    pedidos_preparacion = Pedidos.objects.filter(ped_estado_id=3).count()
    pedidos_enviados = Pedidos.objects.filter(ped_estado_id=4).count()
    pedidos_entregados = Pedidos.objects.filter(ped_estado_id=5).count()
    pedidos_cancelados = Pedidos.objects.filter(ped_estado_id=6).count()
    pedidos_recientes = Pedidos.objects.select_related('usu', 'ped_estado').order_by('-ped_id')[:5]
    for p in pedidos_recientes:
        p.estado_texto = p.ped_estado.est_nombre if p.ped_estado else 'Pendiente'

    context = {
        'total_productos': total_productos,
        'total_usuarios': total_usuarios,
        'total_pedidos': total_pedidos,
        'total_categorias': total_categorias,
        'total_perfiles': total_perfiles,
        'pedidos_pendientes': pedidos_pendientes,
        'pedidos_confirmados': pedidos_confirmados,
        'pedidos_preparacion': pedidos_preparacion,
        'pedidos_enviados': pedidos_enviados,
        'pedidos_entregados': pedidos_entregados,
        'pedidos_cancelados': pedidos_cancelados,
        'pedidos_recientes': pedidos_recientes,
        'guest_checkout_enabled': _guest_checkout_enabled(),
        'section': 'dashboard',
        'sidebar': 0,
    }
    return render(request, 'Admin/panel_dashboard.html', context)


@Login_requerido()
def panel_productos_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    page = int(request.GET.get('page', 1))
    query = request.GET.get('q', '')
    cat_id = request.GET.get('cat', '')
    paginate_by = 10

    queryset = Productos.objects.select_related('cat').all().order_by('prod_id')
    if query:
        queryset = queryset.filter(prod_nombre__icontains=query)
    if cat_id:
        queryset = queryset.filter(cat_id=cat_id)

    paginator = Paginator(queryset, paginate_by)
    productos_page = paginator.get_page(page)

    return render(request, 'Admin/panel_productos.html', {
        'productos': productos_page.object_list,
        'page': page,
        'total_paginas': paginator.num_pages,
        'query': query,
        'cat_id': cat_id,
        'categorias': Categoria.objects.all(),
        'section': 'productos',
        'sidebar': 0,
        'hidden_ids': hidden_products.get_hidden_product_ids(),
    })


@Login_requerido()
def panel_productos_crear(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    if request.method == 'POST':
        form = ProductosForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Producto creado exitosamente.')
                return redirect('panel_productos')
    else:
        form = ProductosForm()

    return render(request, 'Admin/panel_producto_form.html', {
        'form': form,
        'section': 'productos',
        'sidebar': 0,
        'placeholder_images': PLACEHOLDER_IMAGES,
    })


@Login_requerido()
def panel_productos_editar(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    producto = get_object_or_404(Productos, pk=pk)
    if request.method == 'POST':
        form = ProductosForm(request.POST, request.FILES, instance=producto)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Producto actualizado exitosamente.')
                return redirect('panel_productos')
    else:
        form = ProductosForm(instance=producto)

    return render(request, 'Admin/panel_producto_form.html', {
        'form': form,
        'producto': producto,
        'section': 'productos',
        'sidebar': 0,
        'producto_oculto': hidden_products.is_product_hidden(pk),
        'placeholder_images': PLACEHOLDER_IMAGES,
    })


@Login_requerido()
def panel_productos_eliminar(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    producto = get_object_or_404(Productos, pk=pk)
    if request.method == 'POST':
        nombre = producto.prod_nombre
        producto.delete()
        messages.success(request, f'Producto "{nombre}" eliminado permanentemente.')
        return redirect('panel_productos')
    return render(request, 'Admin/panel_producto_confirm_delete.html', {
        'producto': producto,
        'section': 'productos',
        'sidebar': 0,
    })


@Login_requerido()
def panel_usuarios_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    page = int(request.GET.get('page', 1))
    query = request.GET.get('q', '')
    paginate_by = 10

    queryset = Usuarios.objects.select_related('usuario_id_sexo', 'usuario_id_perfil').all().order_by('id_usuario')
    if query:
        queryset = queryset.filter(Q(nombre__icontains=query) | Q(id_usuario__icontains=query))

    paginator = Paginator(queryset, paginate_by)
    usuarios_page = paginator.get_page(page)

    return render(request, 'Admin/panel_usuarios.html', {
        'usuarios': usuarios_page.object_list,
        'page': page,
        'total_paginas': paginator.num_pages,
        'query': query,
        'section': 'usuarios',
        'sidebar': 0,
    })


@Login_requerido()
def panel_usuarios_crear(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    Tipo_Contacto = Config_Contacto.objects.values('id_regla', 'nombre_contacto')

    if request.method == 'POST':
        form = UsuariosForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    usuario = form.save()
                    contactos = request.POST.getlist('contactos_relacionados')
                    if contactos:
                        ContactosCreateView(contactos, usuario.id_usuario)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Usuario creado exitosamente.')
                return redirect('panel_usuarios')
    else:
        form = UsuariosForm()

    return render(request, 'Admin/panel_usuario_form.html', {
        'form': form,
        'Tipo_Contacto': Tipo_Contacto,
        'section': 'usuarios',
        'sidebar': 0,
    })


@Login_requerido()
def panel_usuarios_editar(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    usuario = get_object_or_404(Usuarios, pk=pk)
    contactos = Contactos.objects.filter(id_usuario=usuario)
    Tipo_Contacto = Config_Contacto.objects.values('id_regla', 'nombre_contacto')

    if request.method == 'POST':
        form = UsuariosForm(request.POST, instance=usuario)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                    contactos_data = request.POST.getlist('contactos_relacionados_editados')
                    contactos_actualizar = []
                    for item in contactos_data:
                        parts = item.split(',')
                        if len(parts) == 3:
                            contactos_actualizar.append({
                                'id_contacto': parts[2],
                                'tipo_contacto': parts[0],
                                'dato_contacto': parts[1],
                            })
                    if contactos_actualizar:
                        # Reusamos la funcion existente
                        ContactosUpdateView(contactos_actualizar)
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Usuario actualizado exitosamente.')
                return redirect('panel_usuarios')
    else:
        form = UsuariosForm(instance=usuario)

    return render(request, 'Admin/panel_usuario_form.html', {
        'form': form,
        'usuario': usuario,
        'contactos': contactos,
        'Tipo_Contacto': Tipo_Contacto,
        'section': 'usuarios',
        'sidebar': 0,
    })


@Login_requerido()
def panel_usuarios_detail(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    usuario = get_object_or_404(Usuarios, pk=pk)
    contactos = Contactos.objects.filter(id_usuario=usuario)
    return render(request, 'Admin/panel_usuarios_detail.html', {
        'usuario': usuario,
        'contactos': contactos,
        'section': 'usuarios',
        'sidebar': 0,
    })


@Login_requerido()
def panel_productos_detail(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    producto = get_object_or_404(Productos, pk=pk)
    return render(request, 'Admin/panel_productos_detail.html', {
        'producto': producto,
        'section': 'productos',
        'sidebar': 0,
    })


@Login_requerido()
def panel_pedidos_detail(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    pedido = get_object_or_404(Pedidos, pk=pk)
    productos = PedidosProductos.objects.filter(ped=pedido).select_related('prod')
    contactos = Contactos.objects.filter(id_usuario=pedido.usu)
    estados = EstadoPedidos.objects.all()
    return render(request, 'Admin/panel_pedidos_detail.html', {
        'pedido': pedido,
        'productos': productos,
        'contactos': contactos,
        'estados': estados,
        'section': 'pedidos',
        'sidebar': 0,
    })


@Login_requerido()
def panel_pedidos_cambiar_estado(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')

    TRANSICIONES = {
        1: [2, 6],
        2: [3, 6],
        3: [4, 6],
        4: [5],
        5: [],
        6: [],
    }

    pedido = get_object_or_404(Pedidos, pk=pk)
    if request.method == 'POST':
        try:
            nuevo_estado = int(request.POST.get('nuevo_estado', 0))
        except (TypeError, ValueError):
            messages.error(request, 'Estado inválido.')
            return redirect('panel_pedidos_detalle', pk=pk)

        permitidos = TRANSICIONES.get(pedido.ped_estado_id, [])
        if nuevo_estado not in permitidos:
            messages.error(request, 'Transición no permitida.')
            return redirect('panel_pedidos_detalle', pk=pk)

        try:
            estado = EstadoPedidos.objects.get(pk=nuevo_estado)
        except EstadoPedidos.DoesNotExist:
            messages.error(request, 'Estado inválido.')
        else:
            pedido.ped_estado = estado
            pedido.save()
            messages.success(request, f'Pedido #{pedido.ped_id} → {estado.est_nombre}')
    return redirect('panel_pedidos_detalle', pk=pk)


@Login_requerido()
def panel_pedidos_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')

    estados = EstadoPedidos.objects.all().order_by('pk')
    pedidos = Pedidos.objects.select_related('usu', 'ped_estado').all().order_by('-ped_id')

    estado_filtro = request.GET.get('estado', '')
    q = request.GET.get('q', '')
    fecha_desde = request.GET.get('fecha_desde', '')
    fecha_hasta = request.GET.get('fecha_hasta', '')

    if estado_filtro:
        pedidos = pedidos.filter(ped_estado_id=estado_filtro)
    if q:
        pedidos = pedidos.filter(
            Q(ped_id__icontains=q) | Q(usu__nombre__icontains=q) | Q(usu__id_usuario__icontains=q)
        )
    if fecha_desde:
        pedidos = pedidos.filter(ped_fecha_pedido__gte=fecha_desde)
    if fecha_hasta:
        pedidos = pedidos.filter(ped_fecha_pedido__lte=fecha_hasta)

    pedidos = pedidos[:30]
    for p in pedidos:
        p.estado_texto = p.ped_estado.est_nombre if p.ped_estado else 'Pendiente'

    return render(request, 'Admin/panel_pedidos.html', {
        'pedidos': pedidos,
        'estados': estados,
        'estado_filtro': estado_filtro,
        'q': q,
        'fecha_desde': fecha_desde,
        'fecha_hasta': fecha_hasta,
        'result_count': len(pedidos),
        'section': 'pedidos',
        'sidebar': 0,
    })


@Login_requerido()
def panel_categorias_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    categorias = Categoria.objects.annotate(productos_count=Count('productos')).order_by('cat_id')
    return render(request, 'Admin/panel_categorias.html', {
        'categorias': categorias,
        'section': 'categorias',
        'sidebar': 0,
    })


@Login_requerido()
def panel_categorias_crear(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    if request.method == 'POST':
        form = CategoriaForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Categoría creada exitosamente.')
                return redirect('panel_categorias')
    else:
        form = CategoriaForm()

    return render(request, 'Admin/panel_categoria_form.html', {
        'form': form,
        'section': 'categorias',
        'sidebar': 0,
    })


@Login_requerido()
def panel_categorias_editar(request, pk):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    categoria = get_object_or_404(Categoria, pk=pk)
    if request.method == 'POST':
        form = CategoriaForm(request.POST, instance=categoria)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except DatabaseError as e:
                form.add_error(None, _extract_db_message(e))
            else:
                messages.success(request, 'Categoría actualizada exitosamente.')
                return redirect('panel_categorias')
    else:
        form = CategoriaForm(instance=categoria)

    return render(request, 'Admin/panel_categoria_form.html', {
        'form': form,
        'object': categoria,
        'section': 'categorias',
        'sidebar': 0,
    })


@Login_requerido()
def panel_roles_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    roles = Roles.objects.all().order_by('id_rol')
    return render(request, 'Admin/panel_roles.html', {
        'roles': roles,
        'section': 'roles',
        'sidebar': 0,
    })


@Login_requerido()
def panel_perfiles_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    perfiles = Perfiles.objects.select_related('rol_id').all().order_by('id_perfil')
    return render(request, 'Admin/panel_perfiles.html', {
        'perfiles': perfiles,
        'section': 'perfiles',
        'sidebar': 0,
    })


@Login_requerido()
def panel_sexos_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    sexos = Sexos.objects.all().order_by('id_sexo')
    return render(request, 'Admin/panel_sexos.html', {
        'sexos': sexos,
        'section': 'sexos',
        'sidebar': 0,
    })


@Login_requerido()
def panel_estados_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    estados = EstadoPedidos.objects.all().order_by('id_estado')
    return render(request, 'Admin/panel_estados.html', {
        'estados': estados,
        'section': 'estados',
        'sidebar': 0,
    })


@Login_requerido()
def panel_consultas_list(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta sección.')
        return redirect('home')
    consultas = Consultas_Dinamicas.objects.all().order_by('cons_id')
    return render(request, 'Admin/panel_consultas.html', {
        'consultas': consultas,
        'section': 'consultas',
        'sidebar': 0,
    })


@Login_requerido()
def panel_toggle_guest_checkout(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso.')
        return redirect('home')
    from .models import Configuracion
    config, _ = Configuracion.objects.get_or_create(clave='guest_checkout', defaults={'valor': '1'})
    config.valor = '0' if config.valor == '1' else '1'
    config.save()
    estado = 'activado' if config.valor == '1' else 'desactivado'
    messages.success(request, f'Checkout de invitados {estado}.')
    return redirect('panel_dashboard')


@Login_requerido()
def panel_reportes(request):
    if getattr(request.user, 'usuario_id_perfil_id', None) != 1:
        messages.error(request, 'No tienes permiso para acceder a esta seccion.')
        return redirect('home')

    periodo = request.GET.get('periodo', 'diario')
    desde = request.GET.get('desde', '')
    hasta = request.GET.get('hasta', '')
    estado_sel = request.GET.get('estado', '')
    categoria_sel = request.GET.get('categoria', '')
    preset = request.GET.get('preset', '')

    hoy = date.today()
    presets = {
        'hoy': (hoy.isoformat(), hoy.isoformat(), 'diario'),
        'semana': ((hoy - timedelta(days=hoy.weekday())).isoformat(), hoy.isoformat(), 'diario'),
        'mes': (hoy.replace(day=1).isoformat(), hoy.isoformat(), 'diario'),
        'ano': (hoy.replace(month=1, day=1).isoformat(), hoy.isoformat(), 'mensual'),
        'todo': ('', '', 'mensual'),
    }
    if preset in presets:
        desde, hasta, periodo = presets[preset]

    if not desde and not hasta:
        desde = hoy.replace(day=1).isoformat()
        hasta = hoy.isoformat()

    pedidos = Pedidos.objects.select_related('usu', 'ped_estado').all()
    if desde:
        pedidos = pedidos.filter(ped_fecha_pedido__gte=desde)
    if hasta:
        pedidos = pedidos.filter(ped_fecha_pedido__lte=hasta)
    if estado_sel:
        pedidos = pedidos.filter(ped_estado_id=int(estado_sel))
    if categoria_sel:
        pedidos = pedidos.filter(pedidosproductos__prod__cat_id=categoria_sel).distinct()

    total_ingresos = pedidos.aggregate(total=Sum('ped_total'))['total'] or Decimal('0')
    total_pedidos = pedidos.count()
    promedio_pedido = (total_ingresos / total_pedidos) if total_pedidos > 0 else Decimal('0')

    if periodo == 'diario':
        chart_qs = pedidos.values('ped_fecha_pedido').annotate(
            total=Sum('ped_total'), cantidad=Count('ped_id')
        ).order_by('ped_fecha_pedido')
        labels = [p['ped_fecha_pedido'].strftime('%d/%m') if p['ped_fecha_pedido'] else '' for p in chart_qs]
    elif periodo == 'semanal':
        chart_qs = pedidos.annotate(label=TruncWeek('ped_fecha_pedido')).values('label').annotate(
            total=Sum('ped_total'), cantidad=Count('ped_id')
        ).order_by('label')
        labels = [p['label'].strftime('Sem %W') if p['label'] else '' for p in chart_qs]
    else:
        chart_qs = pedidos.annotate(label=TruncMonth('ped_fecha_pedido')).values('label').annotate(
            total=Sum('ped_total'), cantidad=Count('ped_id')
        ).order_by('label')
        labels = [p['label'].strftime('%b %Y') if p['label'] else '' for p in chart_qs]

    chart_data = {
        'labels': labels,
        'ingresos': [float(p['total'] or 0) for p in chart_qs],
        'pedidos': [p['cantidad'] for p in chart_qs],
    }

    top_productos = PedidosProductos.objects.filter(
        ped__in=pedidos
    ).values('prod__prod_nombre').annotate(
        total_vendido=Sum('pped_total'), cantidad=Sum('pped_cantidad')
    ).order_by('-total_vendido')[:10]

    pedidos_por_estado = pedidos.values('ped_estado__est_nombre').annotate(
        cantidad=Count('ped_id'), total=Sum('ped_total')
    ).order_by('-cantidad')

    if request.GET.get('format') == 'csv':
        from django.http import HttpResponse
        import csv
        response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
        response['Content-Disposition'] = 'attachment; filename="reportes_pedidos.csv"'
        writer = csv.writer(response)
        writer.writerow(['ID Pedido', 'Fecha', 'Usuario', 'Total', 'Estado', 'Direccion', 'Notas'])
        for p in pedidos.order_by('-ped_fecha_pedido'):
            writer.writerow([
                p.ped_id,
                p.ped_fecha_pedido.strftime('%Y-%m-%d') if p.ped_fecha_pedido else '',
                p.usu.nombre if p.usu else '',
                str(p.ped_total or '0'),
                p.ped_estado.est_nombre if p.ped_estado else '',
                p.ped_direccion_envio or '',
                p.ped_notas or '',
            ])
        return response

    estados = EstadoPedidos.objects.all().order_by('est_id')
    categorias = Categoria.objects.all().order_by('cat_id')

    return render(request, 'Admin/panel_reportes.html', {
        'section': 'reportes',
        'sidebar': 0,
        'periodo': periodo,
        'desde': desde,
        'hasta': hasta,
        'estado_sel': estado_sel,
        'categoria_sel': categoria_sel,
        'total_ingresos': total_ingresos,
        'total_pedidos': total_pedidos,
        'promedio_pedido': promedio_pedido,
        'pedidos': pedidos.order_by('-ped_fecha_pedido')[:200],
        'top_productos': top_productos,
        'pedidos_por_estado': pedidos_por_estado,
        'chart_data': json.dumps(chart_data),
        'estados': estados,
        'categorias': categorias,
    })