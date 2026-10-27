# Informe de incidente — SOC / Abuse

**Caso:** {{ case.name }}  
**Ticket SOC:** {{ case.soc_id }}  
**Apertura:** {{ case.open_date }}  
{% if case.close_date %}**Cierre:** {{ case.close_date }}{% endif %}

## Resumen del caso

{{ case.description }}

{% if notes is defined and notes|count %}
## Registro de investigación y resolución

{% for note in notes %}
{% if note.note_content is defined and note.note_content|trim %}
### {{ note.note_title }}

{{ note.note_content }}

{% endif %}
{% endfor %}
{% elif case.notes is defined and case.notes|count %}
## Registro de investigación y resolución

{% for note in case.notes %}
{% if note.note_content is defined and note.note_content|trim %}
### {{ note.note_title }}

{{ note.note_content }}

{% endif %}
{% endfor %}
{% endif %}

{% if evidences is defined and evidences|count %}
## Archivos de evidencia

{% for evidence in evidences %}
- **{{ evidence.filename }}**{% if evidence.file_hash %} — SHA/hash: {{ evidence.file_hash }}{% endif %}{% if evidence.date_added %} — Registro: {{ evidence.date_added }}{% endif %}
{% endfor %}
{% elif case.evidences is defined and case.evidences|count %}
## Archivos de evidencia

{% for evidence in case.evidences %}
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
