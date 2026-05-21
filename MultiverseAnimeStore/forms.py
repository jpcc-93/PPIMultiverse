from django import forms
from .models import Categoria, Contactos, Pedidos, PedidosProductos, Productos, Roles, Usuarios, Sexos, EstadoPedidos, Perfiles, Consultas_Dinamicas, EstadoPedidos
from datetime import date as Date
from django.db import connection, transaction
from django.db.models import Max


def next_int_id(model, field_name):
    """
    Devuelve MAX(field) + 1 para PKs enteras.
    Usa SQL estándar (CAST AS INTEGER) compatible con SQLite y PostgreSQL.
    Envuelto en transacción con select_for_update para evitar race conditions en PostgreSQL.
    """
    table = model._meta.db_table
    sql = f'SELECT MAX(CAST({field_name} AS INTEGER)) FROM "{table}"'
    try:
        with transaction.atomic():
            model.objects.select_for_update().first()
            with connection.cursor() as cursor:
                cursor.execute(sql)
                row = cursor.fetchone()
                maxval = row[0] if row and row[0] is not None else 0
                return int(maxval) + 1
    except Exception:
        return model.objects.count() + 1


def get_next_char_id(model, field_name, prefix):
    """
    Devuelve el próximo ID numérico para campos VARCHAR con formato 'PREFIX-NNN'.
    Usa SUBSTR + CAST para extraer el sufijo numérico y obtener MAX + 1.
    Ej: get_next_char_id(Productos, 'prod_id', 'PROD-') sobre ['PROD-1','PROD-10'] → 11

    Compatible con SQLite y PostgreSQL (SUBSTR y CAST son SQL estándar).
    Envuelto en transacción con select_for_update.
    """
    table = model._meta.db_table
    prefix_len = len(prefix)
    sql = f"""
        SELECT MAX(CAST(SUBSTR({field_name}, {prefix_len + 1}) AS INTEGER))
        FROM "{table}"
        WHERE {field_name} LIKE '{prefix}%'
    """
    with transaction.atomic():
        model.objects.select_for_update().first()
        with connection.cursor() as cursor:
            cursor.execute(sql)
            row = cursor.fetchone()
            maxval = row[0] if row and row[0] is not None else 0
            return maxval + 1


def next_consecutive_id(model, field):
    ids = list(model.objects.order_by(field).values_list(field, flat=True))
    expected = 1

    for id_val in ids:
        if id_val != expected:
            return expected
        expected += 1

    return expected


def get_next_id(value):
    import re
    match = re.search(r'(\d+)$', value)
    if match:
        return int(match.group(1)) + 1
    return 1


def get_next_id_model_name(model, field_name):
    """
    Recibe un modelo y el nombre del campo, obtiene el último valor del campo
    con select_for_update para evitar race conditions en PostgreSQL.
    """
    with transaction.atomic():
        last_obj = model.objects.select_for_update().order_by(f'-{field_name}').first()
        if last_obj:
            value = getattr(last_obj, field_name)
            return get_next_id(value)
        else:
            return 1


class PedidosForm(forms.ModelForm):
    class Meta:
        model = Pedidos
        fields = ['ped_id','usu', 'ped_fecha_pedido', 'ped_total', 'ped_direccion_envio', 'ped_notas']
        widgets = {
            'ped_fecha_pedido': forms.DateInput(attrs={'type': 'date'}),
            'ped_notas': forms.Textarea(attrs={'rows': 4}),
        }
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['usu'].queryset = Usuarios.objects.all()
        self.fields['usu'].label_from_instance = lambda obj: f"{obj.nombre} {obj.primer_apellido}"
        self.fields['usu'].required = True
        self.fields['ped_id'].widget = forms.HiddenInput()
        self.fields['ped_id'].initial = next_int_id(Pedidos, 'ped_id')
        self.fields['ped_total'].widget.attrs['readonly'] = True
        self.fields['ped_total'].initial = 0.00
        self.fields['ped_direccion_envio'].widget.attrs.update({'placeholder': 'Ingrese la dirección de envío'})
        self.fields['ped_direccion_envio'].required = True
        self.fields['ped_notas'].widget.attrs.update({'placeholder': 'Ingrese notas adicionales (opcional)'})
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        self.fields['ped_fecha_pedido'].widget.attrs.update({'class': 'form-control datepicker'})
        self.fields['ped_notas'].widget.attrs.update({'class': 'form-control', 'rows': 4})
        self.fields['ped_total'].widget.attrs.update({'class': 'form-control', 'step': '0.01'})
        self.fields['ped_fecha_pedido'].initial = Date.today()
        self.fields['ped_notas'].required = False

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})
        

class PedidosProductosForm(forms.ModelForm):
    class Meta:
        model = PedidosProductos
        fields = ['ped', 'prod', 'pped_cantidad', 'pped_precio_unitario', 'pped_total', 'pped_descuento', 'pped_estado']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['ped'].queryset = Pedidos.objects.all()
        self.fields['ped'].label_from_instance = lambda obj: f"Pedido {obj.ped_id}"
        self.fields['prod'].queryset = Productos.objects.all()
        self.fields['prod'].label_from_instance = lambda obj: f"{obj.prod_nombre} (ID: {obj.prod_id})"
        self.fields['pped_precio_unitario'].widget.attrs['readonly'] = True
        self.fields['pped_total'].widget.attrs['readonly'] = True
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        self.fields['pped_cantidad'].widget.attrs.update({'min': 1})

        self.fields['pped_descuento'].widget.attrs['readonly'] = True
        self.fields['pped_estado'].queryset = EstadoPedidos.objects.all()
        self.fields['pped_estado'].label_from_instance = lambda obj: f"{obj.est_nombre}"
        self.fields['pped_estado'].initial = 1


class PedidoProductoUpdateForm(forms.ModelForm):
    class Meta:
        model = PedidosProductos
        fields = [
            'ped',                 # solo lectura
            'prod',                # solo lectura
            'pped_cantidad',       # solo lectura
            'pped_precio_unitario',# solo lectura
            'pped_descuento',      # solo lectura
            'pped_total',          # solo lectura
            'pped_fecha_entrega',  # editable
            'pped_estado',         # editable
        ]
        widgets = {
            'pped_fecha_entrega': forms.DateInput(attrs={'type': 'date'}),
        }

    # Campos que deben mostrarse pero no deben poder modificarse
    read_only_fields = [
        'ped',
        'prod',
        'pped_cantidad',
        'pped_precio_unitario',
        'pped_descuento',
        'pped_total'
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Hacer los campos solo lectura
        for field_name in self.read_only_fields:
            field = self.fields[field_name]
            field.disabled = True 


class UsuariosForm(forms.ModelForm):
    class Meta:
        model = Usuarios
        fields = [
            'id_usuario', 'nombre', 'primer_apellido', 'segundo_apellido',
            'fecha_nacimiento', 'password_hash', 'usuario_id_sexo', 'usuario_id_perfil', 'activo'
        ]
        widgets = {
            'fecha_nacimiento': forms.DateInput(attrs={'type': 'date'}),
            'password_hash': forms.PasswordInput(render_value=True),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['usuario_id_sexo'].queryset = Sexos.objects.all()
        self.fields['usuario_id_sexo'].label_from_instance = lambda obj: obj.nombre_sexo
        self.fields['usuario_id_perfil'].queryset = Perfiles.objects.all()
        self.fields['usuario_id_perfil'].label_from_instance = lambda obj: obj.nombre
        self.fields['id_usuario'].widget = forms.HiddenInput()
        self.fields['id_usuario'].initial = "USR-" + str(get_next_char_id(Usuarios, 'id_usuario', 'USR-'))
        self.fields['activo'] = forms.TypedChoiceField(
            coerce=int,
            choices=[(1, 'Sí'), (0, 'No')],
            widget=forms.Select,
            required=False,
            initial=1,
        )
        # Forzar required en campos obligatorios del usuario
        self.fields['nombre'].required = True
        self.fields['primer_apellido'].required = True
        self.fields['password_hash'].required = True
        self.fields['usuario_id_sexo'].required = True
        self.fields['usuario_id_perfil'].required = True
        self.fields['segundo_apellido'].required = False
        self.fields['fecha_nacimiento'].required = False
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        self.fields['fecha_nacimiento'].widget.attrs.update({'class': 'form-control datepicker'})
        self.fields['password_hash'].widget.attrs.update({'placeholder': 'Contraseña'})
        self.fields['activo'].required = False

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})


class CategoriaForm(forms.ModelForm):
    class Meta:
        model = Categoria
        fields = ['cat_id', 'cat_nombre', 'cat_descripcion']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['cat_id'].widget = forms.HiddenInput()
        self.fields['cat_id'].initial = "CAT-" + str(get_next_char_id(Categoria, 'cat_id', 'CAT-'))
        self.fields['cat_nombre'].required = True
        self.fields['cat_descripcion'].required = False
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})


class ProductosForm(forms.ModelForm):
    class Meta:
        model = Productos
        fields = ['prod_id', 'prod_nombre', 'prod_descripcion', 'prod_precio_venta', 'prod_stock', 'cat', 'prod_imagen', 'prod_imagen_url', 'prod_destacado']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['cat'].queryset = Categoria.objects.all()
        self.fields['cat'].label_from_instance = lambda obj: obj.cat_nombre
        self.fields['cat'].required = True
        self.fields['prod_id'].widget = forms.HiddenInput()
        self.fields['prod_id'].initial = "PROD-" + str(get_next_char_id(Productos, 'prod_id', 'PROD-'))
        self.fields['prod_nombre'].required = True
        self.fields['prod_precio_venta'].required = False
        self.fields['prod_stock'].required = False
        self.fields['prod_descripcion'].required = False
        self.fields['prod_imagen'].required = False
        self.fields['prod_imagen'].label = 'Subir imagen desde mi PC (opcional — no recomendado en web)'
        self.fields['prod_imagen_url'].required = False
        self.fields['prod_imagen_url'].label = 'URL de la imagen (recomendado — usar Cloudinary)'
        self.fields['prod_destacado'].required = False
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        self.fields['prod_precio_venta'].widget = forms.TextInput(attrs={'class': 'form-control', 'inputmode': 'numeric'})
        self.fields['prod_imagen_url'].widget.attrs.update({'placeholder': 'https://res.cloudinary.com/.../imagen.jpg'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})

    def clean_prod_imagen(self):
        imagen = self.cleaned_data.get('prod_imagen')
        if imagen:
            if imagen.size > 2 * 1024 * 1024:
                raise forms.ValidationError('La imagen no puede superar los 2 MB.')
        return imagen

    def clean_prod_imagen_url(self):
        url = (self.cleaned_data.get('prod_imagen_url') or '').strip()
        if url and not (url.startswith('http://') or url.startswith('https://')):
            raise forms.ValidationError('La URL debe empezar con http:// o https://')
        return url

    def clean_prod_precio_venta(self):
        valor = self.cleaned_data.get('prod_precio_venta')
        if valor is None or valor == '':
            return 0.00
        return valor

    def clean_prod_stock(self):
        valor = self.cleaned_data.get('prod_stock')
        if valor is None or valor == '':
            return 0
        return valor


class RolesForm(forms.ModelForm):
    class Meta:
        model = Roles
        fields = ['id_rol', 'nombre', 'descripcion']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['id_rol'].widget = forms.HiddenInput()
        self.fields['id_rol'].initial = next_int_id(Roles, 'id_rol')
        self.fields['nombre'].required = True
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})


class PerfilesForm(forms.ModelForm):
    class Meta:
        model = Perfiles
        fields = ['id_perfil', 'nombre','rol_id', 'descripcion']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # roles = Roles.objects.values('id_rol', 'nombre')
        self.fields['rol_id'].queryset = Roles.objects.all()
        self.fields['rol_id'].label_from_instance = lambda obj: obj.nombre
        self.fields['id_perfil'].widget = forms.HiddenInput()
        self.fields['id_perfil'].initial = next_int_id(Perfiles, 'id_perfil')
        self.fields['nombre'].required = True
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})

class EstadoPedidosForm(forms.ModelForm):
    class Meta:
        model = EstadoPedidos
        fields = ['est_id', 'est_nombre']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['est_id'].widget = forms.HiddenInput()
        self.fields['est_id'].initial = next_consecutive_id(EstadoPedidos, 'est_id')
        self.fields['est_id'].widget.attrs.update({'title': 'La id del estado de Entregado debe ser la mayor de todas' })
        self.fields['est_nombre'].required = True
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})


class SexosForm(forms.ModelForm):
    class Meta:
        model = Sexos
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['id_sexo'].widget = forms.HiddenInput()
        self.fields['nombre_sexo'].required = True
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})


class ConsultasDinamicasForm(forms.ModelForm):
    class Meta:
        model = Consultas_Dinamicas
        fields = ['cons_id', 'cons_nombre', 'cons_descripcion', 'cons_sql']
        widgets = {
            'cons_sql': forms.Textarea(attrs={'rows': 5}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['cons_id'].widget = forms.HiddenInput()
        self.fields['cons_id'].initial = next_int_id(Consultas_Dinamicas, 'cons_id')
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})

        self.fields['cons_sql'].widget.attrs.update({'class': 'form-control', 'rows': 5})

    def clean_sql_consulta(self):
        sql = self.cleaned_data['cons_sql']
        return sql


class CambiarContrasenaForm(forms.Form):
    contrasena_actual = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Contraseña actual'}),
        label='Contraseña actual',
        required=True,
        min_length=6,
    )
    contrasena_nueva = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Nueva contraseña'}),
        label='Nueva contraseña',
        required=True,
        min_length=6,
    )
    contrasena_confirmar = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirmar nueva contraseña'}),
        label='Confirmar contraseña',
        required=True,
        min_length=6,
    )

    def clean(self):
        cleaned = super().clean()
        nueva = cleaned.get('contrasena_nueva')
        confirmar = cleaned.get('contrasena_confirmar')
        if nueva and confirmar and nueva != confirmar:
            raise forms.ValidationError('Las contraseñas no coinciden.')
        return cleaned


class PerfilForm(forms.ModelForm):
    class Meta:
        model = Usuarios
        fields = ['nombre', 'primer_apellido', 'segundo_apellido', 'fecha_nacimiento', 'usuario_id_sexo']
        widgets = {
            'fecha_nacimiento': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['usuario_id_sexo'].queryset = Sexos.objects.all()
        self.fields['usuario_id_sexo'].label_from_instance = lambda obj: obj.nombre_sexo
        self.fields['nombre'].required = True
        self.fields['primer_apellido'].required = True
        self.fields['usuario_id_sexo'].required = True
        self.fields['segundo_apellido'].required = False
        self.fields['fecha_nacimiento'].required = False
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        self.fields['fecha_nacimiento'].widget.attrs.update({'class': 'form-control datepicker'})

        for field in self.fields.values():
            field.widget.attrs.update({'placeholder': ' '})
