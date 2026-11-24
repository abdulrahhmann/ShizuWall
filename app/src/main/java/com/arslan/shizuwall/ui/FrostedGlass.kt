package com.arslan.shizuwall.ui

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.RadialGradient
import android.graphics.RenderEffect
import android.graphics.Shader
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import androidx.core.graphics.ColorUtils
import androidx.recyclerview.widget.RecyclerView
import com.arslan.shizuwall.R
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.Chip
import com.google.android.material.color.MaterialColors

/**
 * Applies a cohesive frosted-glass (glassmorphism) layer across activities:
 * - Soft dynamic-color aurora backdrop behind the activity content (GPU-blurred via RenderEffect on API 31+)
 * - Translucent glass fill + luminous 1dp specular hairline border on MaterialCardView surfaces,
 *   search bar, and filter chips (including dynamically recycled RecyclerView items).
 */
object FrostedGlass {

    private const val BACKDROP_TAG = "shizuwall_frosted_backdrop"

    fun applyToActivity(activity: Activity, amoledBlack: Boolean) {
        val contentRoot = activity.findViewById<ViewGroup>(android.R.id.content) ?: return
        val layoutRoot = findPrimaryLayoutRoot(contentRoot) ?: return

        val isDark = (activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES

        val palette = resolvePalette(activity, isDark, amoledBlack)

        installBackdrop(contentRoot, activity, palette, isDark, amoledBlack)
        layoutRoot.setBackgroundColor(Color.TRANSPARENT)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching {
                activity.window?.addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
                activity.window?.attributes = activity.window?.attributes?.apply {
                    blurBehindRadius = 48
                }
            }
        }

        styleHierarchy(layoutRoot, palette)
    }

    private fun findPrimaryLayoutRoot(contentRoot: ViewGroup): View? {
        for (i in 0 until contentRoot.childCount) {
            val child = contentRoot.getChildAt(i)
            if (child.tag != BACKDROP_TAG) return child
        }
        return null
    }

    private fun installBackdrop(
        contentRoot: ViewGroup,
        context: Context,
        palette: GlassPalette,
        isDark: Boolean,
        amoledBlack: Boolean
    ) {
        var backdrop = contentRoot.findViewWithTag<View>(BACKDROP_TAG)
        if (backdrop == null) {
            backdrop = View(context).apply {
                tag = BACKDROP_TAG
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                layoutParams = FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
            }
            contentRoot.addView(backdrop, 0)
        }
        backdrop.background = GlassBackdropDrawable(
            baseColor = palette.backdropBase,
            primaryColor = palette.primary,
            secondaryColor = palette.secondary,
            tertiaryColor = palette.tertiary,
            isDark = isDark,
            amoledBlack = amoledBlack
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            backdrop.setRenderEffect(
                RenderEffect.createBlurEffect(96f, 96f, Shader.TileMode.CLAMP)
            )
        }
    }

    private fun styleHierarchy(view: View, palette: GlassPalette) {
        styleSingleView(view, palette)
        if (view is ViewGroup) {
            for (i in 0 until view.childCount) {
                styleHierarchy(view.getChildAt(i), palette)
            }
            if (view is RecyclerView) {
                attachRecyclerGlassListener(view, palette)
            }
        }
    }

    private fun attachRecyclerGlassListener(recyclerView: RecyclerView, palette: GlassPalette) {
        if (recyclerView.getTag(R.id.tag_frosted_glass_styled) == true) return
        recyclerView.setTag(R.id.tag_frosted_glass_styled, true)
        recyclerView.setOnHierarchyChangeListener(object : ViewGroup.OnHierarchyChangeListener {
            override fun onChildViewAdded(parent: View?, child: View?) {
                if (child != null) styleHierarchy(child, palette)
            }

            override fun onChildViewRemoved(parent: View?, child: View?) = Unit
        })
    }

    private fun styleSingleView(view: View, palette: GlassPalette) {
        when {
            view is MaterialCardView -> styleCard(view, palette)
            view.id == R.id.searchContainer -> styleGlassPill(view, palette)
            view is MaterialToolbar -> view.setBackgroundColor(Color.TRANSPARENT)
            view is Chip -> styleChip(view, palette)
        }
    }

    private fun styleCard(card: MaterialCardView, palette: GlassPalette) {
        if (card.getTag(R.id.tag_frosted_glass_styled) == true) return
        card.setTag(R.id.tag_frosted_glass_styled, true)

        val currentBg = card.cardBackgroundColor.defaultColor
        val baseRgb = if (currentBg == Color.TRANSPARENT) palette.surfaceContainer else currentBg
        val glassFill = ColorUtils.setAlphaComponent(
            ColorUtils.blendARGB(baseRgb, palette.glassTint, 0.14f),
            palette.cardAlpha
        )

        card.setCardBackgroundColor(glassFill)
        card.strokeWidth = palette.strokeWidthPx
        card.strokeColor = palette.borderColor
        card.cardElevation = 0f
    }

    private fun styleGlassPill(view: View, palette: GlassPalette) {
        val density = view.resources.displayMetrics.density
        val topColor = ColorUtils.setAlphaComponent(
            ColorUtils.blendARGB(palette.surfaceContainer, palette.glassTint, 0.22f),
            (palette.cardAlpha + 16).coerceAtMost(235)
        )
        val bottomColor = ColorUtils.setAlphaComponent(palette.surfaceContainer, palette.cardAlpha)
        view.background = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(topColor, bottomColor)
        ).apply {
            cornerRadius = 24f * density
            setStroke(palette.strokeWidthPx, palette.borderColor)
        }
    }

    private fun styleChip(chip: Chip, palette: GlassPalette) {
        if (chip.getTag(R.id.tag_frosted_glass_styled) == true) return
        chip.setTag(R.id.tag_frosted_glass_styled, true)

        val uncheckedFill = ColorUtils.setAlphaComponent(palette.surfaceContainer, palette.cardAlpha)
        val checkedFill = ColorUtils.setAlphaComponent(palette.primaryContainer, (palette.cardAlpha + 45).coerceAtMost(235))
        chip.chipBackgroundColor = ColorStateList(
            arrayOf(
                intArrayOf(android.R.attr.state_checked),
                intArrayOf()
            ),
            intArrayOf(checkedFill, uncheckedFill)
        )
        chip.chipStrokeWidth = palette.strokeWidthPx.toFloat()
        chip.chipStrokeColor = ColorStateList.valueOf(palette.borderColor)
    }

    private data class GlassPalette(
        val backdropBase: Int,
        val surfaceContainer: Int,
        val primary: Int,
        val primaryContainer: Int,
        val secondary: Int,
        val tertiary: Int,
        val glassTint: Int,
        val borderColor: Int,
        val cardAlpha: Int,
        val strokeWidthPx: Int
    )

    private fun resolvePalette(context: Context, isDark: Boolean, amoledBlack: Boolean): GlassPalette {
        val surface = MaterialColors.getColor(
            context,
            com.google.android.material.R.attr.colorSurface,
            if (isDark) Color.parseColor("#111318") else Color.parseColor("#F4F6FA")
        )
        val surfaceContainer = MaterialColors.getColor(
            context,
            com.google.android.material.R.attr.colorSurfaceContainer,
            if (isDark) Color.parseColor("#1D2026") else Color.WHITE
        )
        val primary = MaterialColors.getColor(
            context,
            androidx.appcompat.R.attr.colorPrimary,
            Color.parseColor("#5B8CFF")
        )
        val primaryContainer = MaterialColors.getColor(
            context,
            com.google.android.material.R.attr.colorPrimaryContainer,
            primary
        )
        val secondary = MaterialColors.getColor(
            context,
            com.google.android.material.R.attr.colorSecondary,
            Color.parseColor("#7C6BFF")
        )
        val tertiary = MaterialColors.getColor(
            context,
            com.google.android.material.R.attr.colorTertiary,
            Color.parseColor("#38BDF8")
        )

        val backdropBase = if (amoledBlack && isDark) Color.BLACK else surface
        val glassTint = if (isDark) Color.WHITE else Color.WHITE
        val cardAlpha = when {
            isDark && amoledBlack -> 112 // ~44%
            isDark -> 142 // ~56%
            else -> 182 // ~71%
        }
        val borderColor = if (isDark) {
            ColorUtils.setAlphaComponent(Color.WHITE, 46)
        } else {
            ColorUtils.setAlphaComponent(Color.WHITE, 175)
        }
        val strokeWidthPx = (1f * context.resources.displayMetrics.density).toInt().coerceAtLeast(1)

        return GlassPalette(
            backdropBase = backdropBase,
            surfaceContainer = surfaceContainer,
            primary = primary,
            primaryContainer = primaryContainer,
            secondary = secondary,
            tertiary = tertiary,
            glassTint = glassTint,
            borderColor = borderColor,
            cardAlpha = cardAlpha,
            strokeWidthPx = strokeWidthPx
        )
    }

    private class GlassBackdropDrawable(
        private val baseColor: Int,
        private val primaryColor: Int,
        private val secondaryColor: Int,
        private val tertiaryColor: Int,
        private val isDark: Boolean,
        private val amoledBlack: Boolean
    ) : Drawable() {

        private val basePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = baseColor
            style = Paint.Style.FILL
        }
        private val orbPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.FILL
        }

        override fun draw(canvas: Canvas) {
            val b = bounds
            val w = b.width().toFloat()
            val h = b.height().toFloat()
            if (w <= 0f || h <= 0f) return

            canvas.drawRect(b, basePaint)

            val alphaMain = when {
                isDark && amoledBlack -> 78
                isDark -> 96
                else -> 76
            }
            val alphaAccent = when {
                isDark && amoledBlack -> 64
                isDark -> 82
                else -> 64
            }

            drawOrb(canvas, w * 0.14f, h * 0.12f, w * 0.85f, primaryColor, alphaMain)
            drawOrb(canvas, w * 0.90f, h * 0.44f, w * 0.80f, tertiaryColor, alphaAccent)
            drawOrb(canvas, w * 0.22f, h * 0.86f, w * 0.85f, secondaryColor, alphaAccent)
        }

        private fun drawOrb(canvas: Canvas, cx: Float, cy: Float, radius: Float, color: Int, alpha: Int) {
            val center = ColorUtils.setAlphaComponent(color, alpha)
            val mid = ColorUtils.setAlphaComponent(color, alpha / 3)
            val edge = ColorUtils.setAlphaComponent(color, 0)
            orbPaint.shader = RadialGradient(
                cx,
                cy,
                radius.coerceAtLeast(1f),
                intArrayOf(center, mid, edge),
                floatArrayOf(0f, 0.55f, 1f),
                Shader.TileMode.CLAMP
            )
            canvas.drawCircle(cx, cy, radius, orbPaint)
        }

        override fun setAlpha(alpha: Int) {
            basePaint.alpha = alpha
            orbPaint.alpha = alpha
        }

        override fun setColorFilter(colorFilter: ColorFilter?) {
            basePaint.colorFilter = colorFilter
            orbPaint.colorFilter = colorFilter
        }

        @Deprecated("Deprecated in Java")
        override fun getOpacity(): Int = PixelFormat.OPAQUE
    }
}
