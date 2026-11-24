package com.example.fodtracer.data.database

import android.content.Context
import androidx.room.*
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "diagnostic_sessions")
data class SessionEntity(
    @PrimaryKey val sessionId: String,
    val label: String,
    val createdAtCivilMs: Long,
    val updatedAtCivilMs: Long,
    val deviceModel: String,
    val romType: String,
    val hasLiveTrace: Boolean,
    val anomalyCount: Int,
    val payloadJson: String
)

@Entity(tableName = "comparison_reports")
data class ComparisonEntity(
    @PrimaryKey val comparisonId: String,
    val createdAtCivilMs: Long,
    val archiveALabel: String,
    val archiveBLabel: String,
    val payloadJson: String
)

@Dao
interface FodDao {
    @Query("SELECT * FROM diagnostic_sessions ORDER BY updatedAtCivilMs DESC")
    fun observeSessions(): Flow<List<SessionEntity>>

    @Query("SELECT * FROM diagnostic_sessions WHERE sessionId = :id LIMIT 1")
    suspend fun getSession(id: String): SessionEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSession(entity: SessionEntity)

    @Query("DELETE FROM diagnostic_sessions WHERE sessionId = :id")
    suspend fun deleteSession(id: String)

    @Query("SELECT * FROM comparison_reports ORDER BY createdAtCivilMs DESC")
    fun observeComparisons(): Flow<List<ComparisonEntity>>

    @Query("SELECT * FROM comparison_reports WHERE comparisonId = :id LIMIT 1")
    suspend fun getComparison(id: String): ComparisonEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertComparison(entity: ComparisonEntity)
}

@Database(
    entities = [SessionEntity::class, ComparisonEntity::class],
    version = 1,
    exportSchema = false
)
abstract class FodDatabase : RoomDatabase() {
    abstract fun fodDao(): FodDao

    companion object {
        @Volatile
        private var INSTANCE: FodDatabase? = null

        fun getInstance(context: Context): FodDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    FodDatabase::class.java,
                    "fodtracer.db"
                )
                    .addCallback(object : Callback() {
                        override fun onOpen(db: SupportSQLiteDatabase) {
                            super.onOpen(db)
                            // Guard against Android SQLite CursorWindow (~2MB) crashes caused by
                            // previously persisted oversized rows. Runs inside SQLite before any query.
                            runCatching {
                                db.execSQL("DELETE FROM diagnostic_sessions WHERE length(CAST(payloadJson AS BLOB)) > 1200000")
                                db.execSQL("DELETE FROM comparison_reports WHERE length(CAST(payloadJson AS BLOB)) > 1200000")
                            }
                        }
                    })
                    .build().also { INSTANCE = it }
            }
        }
    }
}
