#include "Variant.h"

QVariantMap qo2qv( const QObject* object, const QStringList& ignoredProperties )
{
    QVariantMap result;
    const QMetaObject *metaobject = object->metaObject();
    int count = metaobject->propertyCount();
    for (int i=0; i<count; ++i) {
        QMetaProperty metaproperty = metaobject->property(i);
        const char *name = metaproperty.name();
 
        if (ignoredProperties.contains(QLatin1String(name)) || (!metaproperty.isReadable()))
            continue;
 
        QVariant value = object->property(name);
        result[QLatin1String(name)] = value;
    }
    return result;
}