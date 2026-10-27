# Informe de incidente — SOC / Abuse

**Caso:** {{ case.name }}  
**Ticket SOC:** {{ case.soc_id }}  
**Apertura:** {{ case.open_date }}  
{% if case.close_date %}**Cierre:** {{ case.close_date }}{% endif %}

{% if case.description %}
{% if '## Resumen' not in case.description and '# Resumen' not in case.description %}
## Resumen del caso

{% endif %}
{{ case.description }}

{% endif %}
{% if notes is defined and notes|count %}
## Registro de notas y seguimiento del incidente

{% for note in notes %}
{% set note_body = note.note_content or note.content or '' %}
{% if note_body|trim %}
### {{ note.note_title or note.title or ('Nota #' ~ loop.index) }}

{{ note_body }}

{% endif %}
{% endfor %}
{% endif %}

{% if iocs is defined and iocs|count %}
## Indicadores de compromiso (IOCs)

| Tipo | Indicador | TLP | Descripción |
|---|---|---|---|
{% for ioc in iocs %}
| `{{ (ioc.ioc_type or ioc.type or 'IOC')|upper }}` | `{{ ioc.ioc_value or ioc.value }}` | {{ ioc.tlp_name or 'AMBER' }} | {{ ioc.ioc_description or ioc.description or 'Detectado en investigación' }} |
{% endfor %}

{% endif %}
{% if evidences is defined and evidences|count %}
## Archivos de evidencia

{% for evidence in evidences %}
- **{{ evidence.filename }}**{% if evidence.file_hash %} — SHA/hash: {{ evidence.file_hash }}{% endif %}{% if evidence.date_added %} — Registro: {{ evidence.date_added }}{% endif %}
{% endfor %}

{% endif %}
{% if evidences_images is defined and evidences_images|count %}
## Evidencias gráficas y capturas (Datastore)

{% for img in evidences_images %}
### {{ img.filename }}
![{{ img.filename }}]({{ img.data_uri }})
*Archivo: `{{ img.filename }}` | SHA-256: `{{ img.sha256 }}`{% if img.description %} — {{ img.description }}{% endif %}*

{% endfor %}
{% endif %}

